# VC issuer
This a VC issuer implemented by the [ZeroTrustVC](https://mm.aueb.gr/projects/zerotrustvc) project.

## Usage

### Prerequisites
The VC issuer is implement in .net 5. Additionally it requires a MySQL database
for storing information related to clients, resources, operations, and authorizations.

### Configure MySQL

All tables have a field called OwnerId which is the identifier of the owner of a
table entry. OwnerId is included in the URL of every request to the VC issuer.

The VC issuer requires the following tables in your database

**client**

| Name | Value |
| --- | --- |
| ID | INT, this is the key|
| Name | Text, a description|
| ClientId | Text, a unique identifier|
| ClientSecret | Text, a client secret|
| OwnerId | Text, an identifier of the owner|

You can generate this table using the following SQL code

```sql
CREATE TABLE `Client` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` text,
  `ClientId` text,
  `ClientSecret` text,
  `OwnerId` text,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
```

**resource**

| Name | Value |
| --- | --- |
| ID | INT, this is the key|
| Name | Text, a description|
|ResourceId| Text, a unique identifier for the resource (e.g., URL). This identifier ends up in the generated token
| OwnerId | Text, an identifier of the owner|

You can generate this table using the following SQL code

```sql
CREATE TABLE `Resource` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` text NOT NULL,
  `ResourceId` text NOT NULL,
  `OwnerId` text,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
```
**operation**

| Name | value |
| --- | --- |
| ID | INT, this is the key|
| Name | Text, a description|
| OperationId | text, a unique identifier for the endpoint. This identifier ends up in the generated token|
| OwnerId | Text, an identifier of the owner|
| ResourceID | INT, foreign key to the resource table|

You can generate this table using the following SQL code

```sql
CREATE TABLE `Operation` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `Name` text NOT NULL,
  `OperationId` text NOT NULL,
  `OwnerId` text,
  `ResourceID` int(11) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IX_Endpoint_ResourceID` (`ResourceID`),
  CONSTRAINT `FK_Endpoint_Resource_ResourceID` FOREIGN KEY (`ResourceID`) REFERENCES `resource` (`ID`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
```

**authorization**

| Name | value |
| --- | --- |
| ID | INT, this is the key|
| OwnerId | Text, an identifier of the owner|
| ClientID | INT, foreign key to the resource table|
| OperationID | INT, foreign key to the operation table|

You can generate this table using the following SQL code

```sql
CREATE TABLE `Authorization` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `OwnerId` text,
  `ClientID` int(11) NOT NULL,
  `OperationID` int(11) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `IX_Authorization_ClientID` (`ClientID`),
  KEY `IX_Authorization_OperationID` (`OperationID`),
  CONSTRAINT `FK_Authorization_Client_ClientID` FOREIGN KEY (`ClientID`) REFERENCES `client` (`ID`) ON DELETE CASCADE,
  CONSTRAINT `FK_Authorization_Endpoint_OperationID` FOREIGN KEY (`OperationID`) REFERENCES `operation` (`ID`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
```

The following SQL script can be used for inserting testing data (for the operation and authorization
entries you may have to enter correct values for the foreign keys)
```sql
INSERT INTO client (Name, ClientId, ClientSecret, OwnerId) VALUES ('Test wallet','wallet','qwerty','mmlab');
INSERT INTO resource (Name, OwnerId) VALUES ('Cloud storage','mmlab');
INSERT INTO operation (Name, OperationId,  OwnerId, ResourceID) VALUES ('Read Files','FL_READ','mmlab','2');
INSERT INTO authorization (OwnerId, ClientID, OperationID ) VALUES ('mmlab','2', '4');
```
### Configuration
Edit the `appsettings.json` file and add a connection string for the MySQL database. For example:

```
"Server=localhost;Database=issuer;User=issuer-user;Password=issuer-password;"
```

Additionally you need to specify in `appsettings.json` a JSON web key that can
be used for singing tokens. You can generate such a jwk in python using jwcrypto
and the following script

```python
from jwcrypto import jwt, jwk, jws
key = jwk.JWK.generate(kty='EC', crv='P-256')
print (key.export(as_dict=True))
```
For example:

```
"jwk": "{'kty': 'EC', 'kid': 'bZll1NPj1dEI1qmcgM1fML0pszfHxjvfD-psfjY4K50', 'crv': 'P-256', 'x': 'sCp_6IGfDeom0_9TxtLC_4elxsyOe6WLMpRYZDcvNtk', 'y': 'iwgCFXsk5yDXRvoCxMdkzTCI-uGm5lOA8c6zfMPsHi0', 'd': '...'}",
```

Finally, you have to specify in `appsettings.json` your issuer identifier (e.g., the
URL of your issuer).

### Compile and run
You can open the source code in Visual Studio or you can use .net sdk to compile it.
Instructions for compiling and running the project follow. In order to compile
the source code, from the project folder execute:

```bash
dotnet build
```

In order to run the compiled file, from the project folder execute:

```bash
dotnet run
```

If you have used the provided SQL commands for filling the database with
test records, you can test that everything works by requesting a token using
the following `curl` command

```bash
curl --insecure -i -u wallet:qwerty -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" http://localhost:5000/oauth2/issue/mmlab
```

**ΝΟΤΕ**

VC issuer should be installed behind a proxy, which will support HTTPS (see
for example the instructions [here](https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/linux-apache?view=aspnetcore-5.0)).