
-- Check out the existence of Service Master Key, Database Master Key
USE master; 
GO

SELECT * FROM sys.symmetric_keys

USE BigData;
GO

--If there is no database master key, create one now.
IF NOT EXISTS
(SELECT * FROM sys.symmetric_keys
WHERE symmetric_key_id = 101)
CREATE MASTER KEY ENCRYPTION
BY PASSWORD = 'Th15i$aS7riN&ofR@nD0m!T3%t'
GO

-----------------------------------
-- 1. Encryption using a Passphrase
-----------------------------------

-- Display the original table
select * from dbo.cust
go
/* Task #1: Show the original table in a screen shot. */


-- Create a copy of the dbo.cust table into cust_encrypt table
-- and define the cardnumber_encrypt column as a varbinary(256)
select fname,
	   lname, 
       cardnumber_encrypt = CONVERT(varbinary(256), cardnumber)
into dbo.cust_encrypt       
from dbo.cust   
where 1 = 2

select  * from dbo.cust_encrypt
go

-- Now, you can populate the cust_encrypt table with rows 
-- from the original table after encrypting using EncryptByPassPhrase function
-- Populate the cust_encrypt table 
declare @passphrase varchar(128)
set @passphrase = 'unencrypted credit card numbers are bad, um-kay'
insert dbo.cust_encrypt
(
       fname, 
       lname, 
       cardnumber_encrypt
)
select 
       fname, 
       lname, 
       cardnumber_encrypt = EncryptByPassPhrase(@passphrase, cardnumber)
from dbo.cust

-- Display the encrypted table
select * from dbo.cust_encrypt
go
/* Task #2: Show the encrypted table in a screen shot. Also, explain why we need to change the data type for encryption. */


--------------------------------------------------------------------------
-- 2. Encryption using Certificate 
-- OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Th15i$aS7riN&ofR@nD0m!T3%t';
-- The DB master key is already open.  
--------------------------------------------------------------------------

-- Create the certificate
USE BigData;
CREATE CERTIFICATE BillingCert 
   WITH SUBJECT = 'Credit Card Billing'
GO

-- Create a symmetric key and encrypt it using the BillingCert certificate
USE BigData;
CREATE SYMMETRIC KEY BillingSymKey WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE BillingCert;
GO

-- Empty out the cust_encrypt table by truncating it
USE BigData;
Truncate table dbo.cust_encrypt

USE BigData;

-- First, decrypt the key using the BillingCert certificate
OPEN SYMMETRIC KEY BillingSymKey
     DECRYPTION BY CERTIFICATE BillingCert

-- Now, insert the rows using the symmetric key encrypted by the certificate
insert dbo.cust_encrypt (
       fname,
       lname,
       cardnumber_encrypt
       )
select 
       fname,
       lname,
       cardnumber_encrypt = EncryptByKey(KEY_GUID('BillingSymKey'),cardnumber)
from dbo.cust

-- Display the encrypted table
select * from dbo.cust_encrypt
go
/* Task #3: Show the encrypted table in a screen shot. Also, explain the encryption process after Task #2. */


-- Now, an authorized user can retrieve the data
USE BigData;
OPEN SYMMETRIC KEY BillingSymKey
     DECRYPTION BY CERTIFICATE BillingCert

-- Display the decrypted table
select fname,
	   lname,
	   cardnumber = convert(nvarchar(25), DecryptByKey(cardnumber_encrypt))
from dbo.cust_encrypt
go
/* Task #4: Show the encrypted table in a screen shot. Also, explain the decryption process after Task #3. 	*/
/* Did you get the original data back? If not, explain how we can get the original data back. 				*/ 


CLOSE SYMMETRIC KEY BillingSymKey

CLOSE MASTER KEY

-- Display the certificates
select * from sys.certificates

-- Display the symmetric keys
select * from sys.symmetric_keys

DROP SYMMETRIC KEY BillingSymKey

DROP CERTIFICATE BillingCert

DROP MASTER KEY

