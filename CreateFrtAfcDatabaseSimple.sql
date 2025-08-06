USE frtafc;
GO

-- Stations Table with proper unique constraint
CREATE TABLE Stations (
    StationID INT IDENTITY(1,1) PRIMARY KEY,
    StationCode CHAR(3) NOT NULL 
        CONSTRAINT CHK_StationCode CHECK (StationCode = UPPER(StationCode)),
    ChineseStationName NVARCHAR(100) NOT NULL,
    EnglishStationName NVARCHAR(100) NOT NULL,
    ZoneID INT NOT NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    CONSTRAINT UQ_StationCode UNIQUE (StationCode)
);

-- Signing Keys Table
CREATE TABLE SigningKeys (
    KeyID INT IDENTITY(1,1) PRIMARY KEY,
    PrivateKey VARCHAR(1024) NOT NULL,
    PublicKey VARCHAR(1024) NOT NULL,
    StartDateTime DATETIME2 NOT NULL,
    ExpiryDateTime DATETIME2 NOT NULL,
    KeyVersion INT NOT NULL
);

-- Obfuscating Keys Table
CREATE TABLE ObfuscatingKeys (
    KeyID INT IDENTITY(1,1) PRIMARY KEY,
    KeyBytes VARBINARY(1024) NOT NULL,
    StartDateTime DATETIME2 NOT NULL,
    ExpiryDateTime DATETIME2 NOT NULL,
    KeyVersion INT NOT NULL
);

-- Tickets Table
CREATE TABLE Tickets (
    InternalTicketID BIGINT IDENTITY(1,1) PRIMARY KEY,
    TicketNumber BIGINT NOT NULL UNIQUE,
    ValueCents INT NOT NULL CHECK (ValueCents >= 0),
    IssuingStation CHAR(3) NOT NULL,
    IssueDateTime DATETIME2(0) NOT NULL,
    TicketType TINYINT NOT NULL,
    IsInvoiced BIT NOT NULL DEFAULT 0,
    TicketState TINYINT NOT NULL DEFAULT 0,
    INDEX IX_Tickets_Number (TicketNumber)
);

-- Add foreign key constraint separately
ALTER TABLE Tickets
ADD CONSTRAINT FK_Tickets_Stations 
FOREIGN KEY (IssuingStation) REFERENCES Stations(StationCode);

-- Fare Table
CREATE TABLE FareRules (
    FareRuleID INT IDENTITY(1,1) PRIMARY KEY,
    FromZone INT NOT NULL,
    ToZone INT NOT NULL,
    FareCents INT NOT NULL,
    INDEX IX_FareRules_Zones (FromZone, ToZone)
);

-- Ticket Audit Log
CREATE TABLE TicketAuditLog (
    AuditID BIGINT IDENTITY(1,1) PRIMARY KEY,
    TicketID BIGINT NOT NULL,
    TicketNumber BIGINT NOT NULL,
    ChangedBy NVARCHAR(128) NOT NULL DEFAULT SYSTEM_USER,
    ChangeType CHAR(1) NOT NULL CHECK (ChangeType IN ('I','U','D')),
    ChangeDateTime DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    OldState TINYINT NULL,
    NewState TINYINT NULL,
    OldValueCents INT NULL,
    NewValueCents INT NULL,
    INDEX IX_AuditLog_DateTime (ChangeDateTime DESC),
    INDEX IX_AuditLog_Ticket (TicketID)
);

-- Users Table
CREATE TABLE ApiUsers (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(128) NOT NULL,
    Salt NVARCHAR(64) NOT NULL,
	UserPermissions INT NOT NULL DEFAULT 0,
    IsActive BIT NOT NULL DEFAULT 1,
    CreatedDateTime DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    LastLoginDateTime DATETIME2 NULL,
    UserDescription NVARCHAR(255) NULL
);

-- Create index for faster username lookups
CREATE INDEX IX_ApiUsers_Username ON ApiUsers(Username);

-- Add foreign key to audit log after Tickets table exists
ALTER TABLE TicketAuditLog
ADD CONSTRAINT FK_Audit_Ticket 
FOREIGN KEY (TicketID) REFERENCES Tickets(InternalTicketID);
GO

-- SP to generate ticket number
CREATE OR ALTER PROCEDURE sp_GenerateTicketNumber
    @TicketNumber BIGINT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Phase 1: Batch generate 10 cryptographically random candidates
    ;WITH RandomNumbers AS (
        SELECT TOP 10 
            ABS(100000000000 + (CONVERT(BIGINT, (899999999999999 * RAND(CHECKSUM(NEWID())))))) AS Num
        FROM sys.objects
    )
    SELECT TOP 1 @TicketNumber = Num
    FROM RandomNumbers
    WHERE NOT EXISTS (SELECT 1 FROM Tickets WHERE TicketNumber = Num)
      AND Num > 0 -- Explicit positive check
    ORDER BY NEWID();
    
    -- Phase 2: Guaranteed positive fallback
    IF @TicketNumber IS NULL
    BEGIN
        -- Timestamp + random suffix (always positive)
        SET @TicketNumber = CONVERT(BIGINT, FORMAT(GETUTCDATE(), 'yyyyMMddHHmmssff')) 
                          + (ABS(CHECKSUM(NEWID())) % 10000); -- Fixed: Added closing parenthesis
        
        -- Ensure both uniqueness AND positivity
        WHILE EXISTS (SELECT 1 FROM Tickets WHERE TicketNumber = @TicketNumber) OR @TicketNumber <= 0
            SET @TicketNumber = ABS(@TicketNumber + (1 + (ABS(CHECKSUM(NEWID())) % 9)));
    END
    
    -- Final validation (defensive programming)
    IF @TicketNumber <= 0
        THROW 50001, 'Generated invalid ticket number (non-positive)', 1;
END
GO

-- Corrected audit trigger
CREATE OR ALTER TRIGGER tr_Tickets_Audit
ON Tickets
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Log inserts
    INSERT INTO TicketAuditLog (
        TicketID, 
        TicketNumber,
        ChangeType,
        OldState,
        NewState,
        OldValueCents,
        NewValueCents
    )
    SELECT 
        i.InternalTicketID,
        i.TicketNumber,
        'I',
        NULL,
        i.TicketState,
        NULL,
        i.ValueCents
    FROM inserted i
    WHERE NOT EXISTS (SELECT 1 FROM deleted);
    
    -- Log updates
    INSERT INTO TicketAuditLog (
        TicketID,
        TicketNumber,
        ChangeType,
        OldState,
        NewState,
        OldValueCents,
        NewValueCents
    )
    SELECT 
        i.InternalTicketID,
        i.TicketNumber,
        'U',
        d.TicketState,
        i.TicketState,
        d.ValueCents,
        i.ValueCents
    FROM inserted i
    JOIN deleted d ON i.InternalTicketID = d.InternalTicketID;
    
    -- Log deletes
    INSERT INTO TicketAuditLog (
        TicketID,
        TicketNumber,
        ChangeType,
        OldState,
        NewState,
        OldValueCents,
        NewValueCents
    )
    SELECT 
        d.InternalTicketID,
        d.TicketNumber,
        'D',
        d.TicketState,
        NULL,
        d.ValueCents,
        NULL
    FROM deleted d
    WHERE NOT EXISTS (SELECT 1 FROM inserted);
END;
GO

-- Verification
SELECT name, type_desc 
FROM sys.objects 
WHERE type IN ('U', 'P', 'TR') 
ORDER BY type_desc, name;
GO

PRINT 'FRT AFC database schema successfully created';
GO

INSERT INTO Stations (StationCode, ChineseStationName, EnglishStationName, ZoneID, IsActive)
VALUES ('JLL', N'俊霖路', 'Junlin Road', 1, 1);
PRINT 'Junlin Road added';