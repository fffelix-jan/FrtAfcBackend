#!/usr/bin/env python3
"""
FRT AFC API User Management Script
Handles user creation/deletion via direct SQL Server connection
Supports CSV import for bulk user creation
"""

import pyodbc
import hashlib
import secrets
import base64
import csv
import sys
import argparse
import os
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime

def load_env_file():
    """Load environment variables from .env file"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Change this to the path of your .env file as necessary
    # The default code is for when running from the repo during development
    # If running from a different location, adjust the path accordingly
    env_file = os.path.join(script_dir, 'FrtAfcBackend', '.env')
    
    env_vars = {}
    try:
        with open(env_file, 'r', encoding='utf-8') as file:
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
        
        print(f"✅ Loaded {len(env_vars)} environment variables from {env_file}")
        
        # Set environment variables
        for key, value in env_vars.items():
            os.environ[key] = value
            
        return env_vars
        
    except FileNotFoundError:
        print(f"❌ Error: .env file not found at {env_file}")
        print("Make sure the .env file exists in the FrtAfcBackend directory")
        return {}
    except Exception as e:
        print(f"❌ Error reading .env file: {e}")
        return {}

def parse_connection_string(conn_str: str) -> Dict[str, str]:
    """Parse SQL Server connection string into components."""
    components = {}
    for part in conn_str.split(';'):
        if '=' in part:
            key, value = part.split('=', 1)
            components[key.strip().lower()] = value.strip()
    return components

def get_pyodbc_connection_string(env_vars: Dict[str, str]) -> str:
    """Convert .NET connection string to pyodbc format."""
    if 'SQLSERVER_CONNECTION_STRING' not in env_vars:
        print("❌ Error: SQLSERVER_CONNECTION_STRING not found in .env file")
        return ""
    
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

# Permission constants matching C# enum
class ApiPermissions:
    NONE = 0
    VIEW_STATIONS = 1 << 0              # 0x0001
    VIEW_FARES = 1 << 1                 # 0x0002
    ISSUE_FULL_FARE_TICKETS = 1 << 2    # 0x0004
    ISSUE_STUDENT_TICKETS = 1 << 3      # 0x0008
    ISSUE_SENIOR_TICKETS = 1 << 4       # 0x0010
    ISSUE_FREE_ENTRY_TICKETS = 1 << 5   # 0x0020
    ISSUE_DAY_PASS_TICKETS = 1 << 6     # 0x0040
    REISSUE_TICKETS = 1 << 7            # 0x0080
    VIEW_TICKETS = 1 << 8               # 0x0100
    VALIDATE_TICKETS = 1 << 9           # 0x0200
    CHANGE_PASSWORD = 1 << 10           # 0x0400
    SYSTEM_ADMIN = 0x7FFFFFFF
    
    # Convenience combinations
    BASIC_USER = VIEW_STATIONS | VIEW_FARES | VIEW_TICKETS
    TICKET_OPERATOR = (BASIC_USER | ISSUE_FULL_FARE_TICKETS | ISSUE_STUDENT_TICKETS | 
                      ISSUE_SENIOR_TICKETS | ISSUE_FREE_ENTRY_TICKETS | ISSUE_DAY_PASS_TICKETS | 
                      REISSUE_TICKETS | VALIDATE_TICKETS | CHANGE_PASSWORD)
    TICKET_VENDING_MACHINE = BASIC_USER | ISSUE_FULL_FARE_TICKETS
    FAREGATE = BASIC_USER | VALIDATE_TICKETS

@dataclass
class ApiUser:
    username: str
    password: str
    permissions: int
    description: Optional[str] = None

class UserManager:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    def _generate_salt(self) -> bytes:
        """Generate a random 32-byte salt"""
        return secrets.token_bytes(32)
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """Hash password using PBKDF2-SHA256 (matching C# implementation)"""
        # Use the same parameters as C# implementation
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 10000, 64)
        return base64.b64encode(hash_bytes).decode('ascii')
    
    def create_user(self, user: ApiUser) -> bool:
        """Create a new API user"""
        try:
            with pyodbc.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                
                # Generate salt and hash password
                salt = self._generate_salt()
                salt_b64 = base64.b64encode(salt).decode('ascii')
                password_hash = self._hash_password(user.password, salt)
                
                # Insert user
                cursor.execute("""
                    INSERT INTO ApiUsers (Username, PasswordHash, Salt, UserPermissions, IsActive, UserDescription)
                    VALUES (?, ?, ?, ?, 1, ?)
                """, user.username, password_hash, salt_b64, user.permissions, user.description)
                
                conn.commit()
                print(f"✅ User '{user.username}' created successfully")
                return True
                
        except pyodbc.IntegrityError as e:
            if "UNIQUE" in str(e):
                print(f"❌ User '{user.username}' already exists")
            else:
                print(f"❌ Database error: {e}")
            return False
        except Exception as e:
            print(f"❌ Error creating user '{user.username}': {e}")
            return False
    
    def deactivate_user(self, username: str) -> bool:
        """Deactivate a user (soft delete)"""
        try:
            with pyodbc.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                
                cursor.execute("UPDATE ApiUsers SET IsActive = 0 WHERE Username = ?", username)
                
                if cursor.rowcount > 0:
                    conn.commit()
                    print(f"✅ User '{username}' deactivated successfully")
                    return True
                else:
                    print(f"❌ User '{username}' not found")
                    return False
                    
        except Exception as e:
            print(f"❌ Error deactivating user '{username}': {e}")
            return False
    
    def list_users(self) -> List[Dict]:
        """List all users"""
        try:
            with pyodbc.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT Id, Username, UserPermissions, IsActive, CreatedDateTime, 
                           LastLoginDateTime, UserDescription
                    FROM ApiUsers 
                    ORDER BY Username
                """)
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'id': row.Id,
                        'username': row.Username,
                        'permissions': row.UserPermissions,
                        'is_active': row.IsActive,
                        'created': row.CreatedDateTime,
                        'last_login': row.LastLoginDateTime,
                        'description': row.UserDescription
                    })
                
                return users
                
        except Exception as e:
            print(f"❌ Error listing users: {e}")
            return []
    
    def import_from_csv(self, csv_file: str) -> int:
        """Import users from CSV file"""
        created_count = 0
        
        try:
            with open(csv_file, 'r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                # Expected columns: username, password, permissions, description
                for row_num, row in enumerate(reader, 2):  # Start at 2 since header is row 1
                    try:
                        username = row['username'].strip()
                        password = row['password'].strip()
                        permissions = int(row['permissions'].strip())
                        description = row.get('description', '').strip() or None
                        
                        user = ApiUser(username, password, permissions, description)
                        if self.create_user(user):
                            created_count += 1
                            
                    except (KeyError, ValueError) as e:
                        print(f"⚠️  Skipping row {row_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            print(f"❌ CSV file '{csv_file}' not found")
        except Exception as e:
            print(f"❌ Error reading CSV file: {e}")
        
        return created_count

def show_permission_values():
    """Display permission values for reference"""
    print("🔐 Permission Values Reference")
    print("=" * 50)
    print(f"VIEW_STATIONS = {ApiPermissions.VIEW_STATIONS}")
    print(f"VIEW_FARES = {ApiPermissions.VIEW_FARES}")
    print(f"ISSUE_FULL_FARE_TICKETS = {ApiPermissions.ISSUE_FULL_FARE_TICKETS}")
    print(f"ISSUE_STUDENT_TICKETS = {ApiPermissions.ISSUE_STUDENT_TICKETS}")
    print(f"ISSUE_SENIOR_TICKETS = {ApiPermissions.ISSUE_SENIOR_TICKETS}")
    print(f"ISSUE_FREE_ENTRY_TICKETS = {ApiPermissions.ISSUE_FREE_ENTRY_TICKETS}")
    print(f"ISSUE_DAY_PASS_TICKETS = {ApiPermissions.ISSUE_DAY_PASS_TICKETS}")
    print(f"REISSUE_TICKETS = {ApiPermissions.REISSUE_TICKETS}")
    print(f"VIEW_TICKETS = {ApiPermissions.VIEW_TICKETS}")
    print(f"VALIDATE_TICKETS = {ApiPermissions.VALIDATE_TICKETS}")
    print(f"CHANGE_PASSWORD = {ApiPermissions.CHANGE_PASSWORD}")
    print(f"SYSTEM_ADMIN = {ApiPermissions.SYSTEM_ADMIN}")
    print()
    print("Combinations:")
    print(f"BASIC_USER = {ApiPermissions.BASIC_USER}")
    print(f"TICKET_OPERATOR = {ApiPermissions.TICKET_OPERATOR}")
    print(f"TICKET_VENDING_MACHINE = {ApiPermissions.TICKET_VENDING_MACHINE}")
    print(f"FAREGATE = {ApiPermissions.FAREGATE}")

def main():
    parser = argparse.ArgumentParser(description='FRT AFC API User Management')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create user command
    create_parser = subparsers.add_parser('create', help='Create a new user')
    create_parser.add_argument('username', help='Username')
    create_parser.add_argument('password', help='Password')
    create_parser.add_argument('permissions', type=int, help='Permission value')
    create_parser.add_argument('--description', help='User description')
    
    # Deactivate user command
    deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate a user')
    deactivate_parser.add_argument('username', help='Username to deactivate')
    
    # List users command
    list_parser = subparsers.add_parser('list', help='List all users')
    
    # Import CSV command
    import_parser = subparsers.add_parser('import', help='Import users from CSV')
    import_parser.add_argument('csv_file', help='Path to CSV file')
    
    # Show permissions command
    perms_parser = subparsers.add_parser('permissions', help='Show permission values')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'permissions':
        show_permission_values()
        return
    
    # Load environment variables from .env file using the working logic
    env_vars = load_env_file()
    
    # Get connection string using the working conversion logic
    connection_string = get_pyodbc_connection_string(env_vars)
    if not connection_string:
        print("❌ Could not get connection string from environment")
        connection_string = input("Enter SQL Server connection string: ")
        if not connection_string:
            print("❌ No connection string provided")
            sys.exit(1)
    
    try:
        manager = UserManager(connection_string)
        
        if args.command == 'create':
            user = ApiUser(args.username, args.password, args.permissions, args.description)
            if not manager.create_user(user):
                sys.exit(1)
                
        elif args.command == 'deactivate':
            if not manager.deactivate_user(args.username):
                sys.exit(1)
                
        elif args.command == 'list':
            users = manager.list_users()
            if users:
                print(f"📋 Found {len(users)} users:")
                print(f"{'ID':<4} {'Username':<20} {'Permissions':<12} {'Active':<6} {'Description':<30}")
                print("-" * 80)
                for user in users:
                    active = "Yes" if user['is_active'] else "No"
                    desc = user['description'] or ""
                    print(f"{user['id']:<4} {user['username']:<20} {user['permissions']:<12} {active:<6} {desc:<30}")
            else:
                print("No users found")
                
        elif args.command == 'import':
            created = manager.import_from_csv(args.csv_file)
            print(f"📊 Import completed: {created} users created")
            
    except pyodbc.Error as e:
        print(f"❌ Database connection error: {e}")
        print("💡 Make sure SQL Server ODBC driver is installed and connection string is correct")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()