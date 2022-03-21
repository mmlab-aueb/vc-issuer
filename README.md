# VC issuer
This a VC issuer implemented by the [ZeroTrustVC](https://mm.aueb.gr/projects/zerotrustvc) project.

## Usage

### Prerequisites
The VC issuer is implement in .net 5. Additionally it requires a MySQL database
for storing information related to clients, resources, operations, and authorizations.

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

### Create database

**NOTE** The following will delete any existing tables.

From the project folder run:

```
dotnet ef database update
```
If `ef` is not available, install it using  the command `dotnet tool install --global dotnet-ef`

The following SQL statements can be used as test data (it is assumed that the created tables are empty).

```sql
INSERT INTO endpoint (ID, Name, URI) VALUES ('1', 'Cloud Storage', 'https://www.example.com/cloud');
INSERT INTO client (ID, Name, ClientId, ClientSecret) VALUES ('1', 'Test wallet','wallet','qwerty');
INSERT INTO resource (ID, Name, URI, EndpointID) VALUES ('1','Folders in Cloud Storage', 'Folder','1');
INSERT INTO operation (ID, Name, URI, ResourceID) VALUES ('1','List items', 'List','1');
INSERT INTO authorization (ID, ClientID, OperationID) VALUES ('1','1', '1');
```


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

## GUI
You can use [vc-issuer-gui](https://github.com/mmlab-aueb/vc-issuer-gui) for managing VC issuer.