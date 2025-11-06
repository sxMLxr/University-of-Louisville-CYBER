 
USE master;
GO;

IF EXISTS(select * from sys.databases where name='BigData')
DROP DATABASE BigData
GO

CREATE DATABASE BigData
Go
USE BigData
GO

/* Login Table Creation */
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'login')
DROP TABLE dbo.login
GO

CREATE TABLE dbo.login (
	loginid int identity(100,1) not null,
	login_name varchar(max) null,
	password varchar(max) null
) 
GO

INSERT INTO login 
VALUES 
	('admin','apple'),
	('user1','orangle'),
	('user2','mango'),
	('user3','blueberry'),
	('user4','tomato');
GO

SELECT * FROM dbo.login
ORDER BY loginid ASC


/* Product Table Creation */
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'product')
DROP TABLE dbo.product
GO

CREATE TABLE dbo.product(
	p_id 		int identity(100,1) not null,
	p_name 		VARCHAR(50) NOT NULL,
	p_cat 		VARCHAR(50) NOT NULL,
	p_price		INT NOT NULL,
)
GO
	
INSERT INTO dbo.product (p_name, p_cat, p_price)
VALUES 
	('milk1', 'milk', 10), 
	('milk2', 'milk', 20), 
	('milk3', 'milk', 30), 
	('candy1', 'candy', 40), 
	('candy1', 'candy', 50), 
	('candy1', 'candy', 60); 
GO

SELECT * FROM dbo.product
ORDER BY p_cat ASC

	
/* Customer Table Creation */
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'cust')
DROP TABLE dbo.cust
GO

CREATE TABLE dbo.cust(
	cust_id 		int identity(100,1) not null,
	fname 		VARCHAR(50) null,
	lname 		VARCHAR(50) null,
	cardnumber		VARCHAR(25) null,
) 
GO

INSERT INTO cust (fname, lname, cardnumber)
VALUES 
	('Paul', 'Samuelson', 1111111111), 
	('Adam', 'Smith', 2222222222), 
	('Milton', 'Friedman', 3333333333), 
	('Gary', 'Becker', 4444444444), 
	('Daniel', 'Kahneman', 5555555555);
GO

SELECT * FROM dbo.cust
ORDER BY cust_id ASC
