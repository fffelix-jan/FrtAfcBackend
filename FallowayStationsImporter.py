#!/usr/bin/env python3
"""
Station Data Import Script for FRT AFC System
Imports station data from FallowayStations.txt into SQL Server database.

TSV Format Expected (Excel "Unicode Text"):
Column 1: English Station Name
Column 2: Chinese Station Name  
Column 3: Station Code
Column 4: (ignored)
Column 5: Zone ID

First row (headers) is skipped.
All stations are set as active (IsActive = 1).
"""

import csv
import pyodbc
import sys
import os
from typing import List, Tuple, Dict

def load_env_file(env_path: str) -> Dict[str, str]:
    """
    Load environment variables from .env file.
    Returns dictionary of key-value pairs.
    """
    env_vars = {}
    try:
        with open(env_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE format
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
                else:
                    print(f"Warning: Invalid format in .env file line {line_num}: {line}")
        
        print(f"✅ Loaded {len(env_vars)} environment variables from {env_path}")
        return env_vars
        
    except FileNotFoundError:
        print(f"❌ Error: .env file not found at {env_path}")
        print("Make sure the .env file exists in the FrtAfcBackend directory")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading .env file: {e}")
        sys.exit(1)

def parse_connection_string(conn_str: str) -> Dict[str, str]:
    """
    Parse SQL Server connection string into components.
    """
    components = {}
    for part in conn_str.split(';'):
        if '=' in part:
            key, value = part.split('=', 1)
            components[key.strip().lower()] = value.strip()
    return components

def get_pyodbc_connection_string(env_vars: Dict[str, str]) -> str:
    """
    Convert .NET connection string to pyodbc format.
    """
    if 'SQLSERVER_CONNECTION_STRING' not in env_vars:
        print("❌ Error: SQLSERVER_CONNECTION_STRING not found in .env file")
        sys.exit(1)
    
    dotnet_conn_str = env_vars['SQLSERVER_CONNECTION_STRING']
    components = parse_connection_string(dotnet_conn_str)
    
    # Map .NET connection string components to pyodbc format
    server = components.get('server', 'localhost')
    database = components.get('database', 'frtafc')
    user_id = components.get('user id', 'sa')
    password = components.get('password', '')
    encrypt = 'yes' if components.get('encrypt', 'false').lower() == 'true' else 'no'
    trust_cert = 'yes' if components.get('trustservercertificate', 'false').lower() == 'true' else 'no'
    
    # Build pyodbc connection string
    pyodbc_conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={user_id};"
        f"PWD={password};"
        f"Encrypt={encrypt};"
        f"TrustServerCertificate={trust_cert};"
    )
    
    print(f"🔗 Connecting to: {server}/{database}")
    return pyodbc_conn_str

def validate_station_code(station_code: str) -> str:
    """Validate and normalize station code."""
    if not station_code or len(station_code.strip()) != 3:
        raise ValueError(f"Station code must be exactly 3 characters: '{station_code}'")
    
    normalized = station_code.strip().upper()
    if not normalized.isalpha():
        raise ValueError(f"Station code must contain only letters: '{station_code}'")
    
    return normalized

def read_stations_tsv(tsv_file_path: str) -> List[Tuple[str, str, str, int]]:
    """
    Read station data from TSV file (Excel Unicode Text format).
    
    Returns list of tuples: (english_name, chinese_name, station_code, zone_id)
    """
    stations = []
    
    try:
        # Open with multiple encoding attempts
        encodings_to_try = ['utf-16', 'utf-16le', 'utf-16be', 'utf-8', 'utf-8-sig']
        file_content = None
        used_encoding = None
        
        for encoding in encodings_to_try:
            try:
                with open(tsv_file_path, 'r', encoding=encoding) as file:
                    file_content = file.read()
                    used_encoding = encoding
                    break
            except (UnicodeError, UnicodeDecodeError):
                continue
        
        if file_content is None:
            raise ValueError("Could not decode file with any supported encoding")
        
        print(f"📖 Successfully opened file with {used_encoding} encoding")
        
        # Split content into lines and process with tab delimiter
        lines = file_content.splitlines()
        csv_reader = csv.reader(lines, delimiter='\t')
        
        # Skip header row
        try:
            header = next(csv_reader)
            print(f"📋 Skipped header row: {header[:3]}... (showing first 3 columns)")
        except StopIteration:
            print("⚠️  Warning: File appears to be empty")
            return stations
        
        row_num = 1  # Start at 1 since we skipped header
        for row in csv_reader:
            row_num += 1
            
            # Skip empty rows
            if not row or all(not str(cell).strip() for cell in row):
                continue
            
            if len(row) < 5:
                print(f"⚠️  Row {row_num}: insufficient columns ({len(row)}), skipping")
                continue
            
            try:
                english_name = str(row[0]).strip()
                chinese_name = str(row[1]).strip() 
                station_code = validate_station_code(str(row[2]))
                zone_id = int(str(row[4]).strip())
                
                if not english_name:
                    raise ValueError("English station name cannot be empty")
                if not chinese_name:
                    raise ValueError("Chinese station name cannot be empty")
                if zone_id <= 0:
                    raise ValueError(f"Zone ID must be positive, got: {zone_id}")
                
                stations.append((english_name, chinese_name, station_code, zone_id))
                print(f"✅ Parsed: {station_code} - {english_name} ({chinese_name}) - Zone {zone_id}")
                
            except (ValueError, IndexError) as e:
                print(f"❌ Row {row_num} error: {e}")
                continue
            
    except FileNotFoundError:
        print(f"❌ Error: Station file '{tsv_file_path}' not found")
        print("Make sure FallowayStations.txt exists in the same directory as this script")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading station file: {e}")
        sys.exit(1)
    
    return stations

def insert_stations(stations: List[Tuple[str, str, str, int]], connection_string: str) -> None:
    """Insert station data into SQL Server database."""
    
    if not stations:
        print("⚠️  No valid stations to insert")
        return
    
    try:
        with pyodbc.connect(connection_string) as conn:
            cursor = conn.cursor()
            
            # Check if stations already exist and get counts
            cursor.execute("SELECT COUNT(*) FROM Stations")
            existing_count = cursor.fetchone()[0]
            
            insert_sql = """
                INSERT INTO Stations (StationCode, ChineseStationName, EnglishStationName, ZoneID, IsActive)
                VALUES (?, ?, ?, ?, 1)
            """
            
            inserted_count = 0
            duplicate_count = 0
            
            for english_name, chinese_name, station_code, zone_id in stations:
                try:
                    # Check for existing station code
                    cursor.execute("SELECT COUNT(*) FROM Stations WHERE StationCode = ?", station_code)
                    if cursor.fetchone()[0] > 0:
                        print(f"⚠️  Station code '{station_code}' already exists, skipping")
                        duplicate_count += 1
                        continue
                    
                    # Insert new station
                    cursor.execute(insert_sql, station_code, chinese_name, english_name, zone_id)
                    inserted_count += 1
                    print(f"✅ Inserted: {station_code} - {english_name} ({chinese_name}) - Zone {zone_id}")
                    
                except pyodbc.IntegrityError as e:
                    print(f"❌ Integrity error for {station_code}: {e}")
                    duplicate_count += 1
                    continue
            
            # Commit all changes
            conn.commit()
            
            # Summary
            print(f"\n{'='*60}")
            print(f"📊 IMPORT SUMMARY")
            print(f"{'='*60}")
            print(f"📋 Stations processed: {len(stations)}")
            print(f"✅ Successfully inserted: {inserted_count}")
            print(f"⚠️  Duplicates/errors skipped: {duplicate_count}")
            print(f"🗃️  Database stations before: {existing_count}")
            print(f"🗃️  Database stations after: {existing_count + inserted_count}")
            print(f"{'='*60}")
            
    except pyodbc.Error as e:
        print(f"❌ Database error: {e}")
        print("Make sure:")
        print("  - SQL Server is running and accessible")
        print("  - Database 'frtafc' exists")
        print("  - Login credentials are correct")
        print("  - ODBC Driver 17 for SQL Server is installed")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

def main():
    """Main execution function."""
    print("🚇 Falloway Rapid Transit - Station Import Tool")
    print("=" * 50)
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define file paths
    stations_file = os.path.join(script_dir, 'FallowayStations.txt')
    env_file = os.path.join(script_dir, 'FrtAfcBackend', '.env')
    
    print(f"📂 Station file: {stations_file}")
    print(f"⚙️  Environment file: {env_file}")
    print()
    
    # Load environment variables
    env_vars = load_env_file(env_file)
    
    # Get database connection string
    connection_string = get_pyodbc_connection_string(env_vars)
    
    # Read station data
    print(f"📖 Reading station data from: {stations_file}")
    stations = read_stations_tsv(stations_file)
    
    if not stations:
        print("❌ No valid station data found")
        sys.exit(1)
    
    print(f"\n✅ Found {len(stations)} valid stations")
    
    # Confirm before proceeding
    print(f"\n⚠️  About to insert {len(stations)} stations into the database.")
    response = input("Continue? (y/N): ")
    if response.lower() != 'y':
        print("❌ Import cancelled by user")
        sys.exit(0)
    
    # Insert stations
    insert_stations(stations, connection_string)
    print("\n🎉 Station import completed successfully!")

if __name__ == "__main__":
    main()