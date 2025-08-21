-- Run this AFTER you created the database.
-- Insert fare rules for zones 1 and 2
-- Travel within Zone 1: 200 cents
-- Travel within Zone 2: 300 cents  
-- Travel between Zone 1 and Zone 2: 300 cents

USE frtafc;
GO

-- Clear existing fare rules (optional, remove if you want to keep existing data)
DELETE FROM FareRules;

-- Insert fare rules
INSERT INTO FareRules (FromZone, ToZone, FareCents) VALUES
-- Within Zone 1
(1, 1, 200),
-- Within Zone 2  
(2, 2, 300),
-- Between Zone 1 and Zone 2 (both directions)
(1, 2, 300),
(2, 1, 300);

-- Verify the inserted data
SELECT FromZone, ToZone, FareCents,
       CASE 
           WHEN FromZone = ToZone THEN 'Within Zone ' + CAST(FromZone AS VARCHAR)
           ELSE 'Between Zone ' + CAST(FromZone AS VARCHAR) + ' and Zone ' + CAST(ToZone AS VARCHAR)
       END AS TravelType
FROM FareRules 
ORDER BY FromZone, ToZone;

PRINT 'Fare rules inserted successfully:';
PRINT '- Zone 1 to Zone 1: 200 cents';  
PRINT '- Zone 2 to Zone 2: 200 cents';
PRINT '- Zone 1 to Zone 2: 300 cents';
PRINT '- Zone 2 to Zone 1: 300 cents';
GO