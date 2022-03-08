using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

namespace vc_issuer.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "client",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    Name = table.Column<string>(type: "text", nullable: true),
                    ClientId = table.Column<string>(type: "text", nullable: true),
                    ClientSecret = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client", x => x.ID);
                });

            migrationBuilder.CreateTable(
                name: "credential",
                columns: table => new
                {
                    jti = table.Column<string>(type: "varchar(767)", nullable: false),
                    exp = table.Column<long>(type: "bigint", nullable: false),
                    iat = table.Column<long>(type: "bigint", nullable: false),
                    aud = table.Column<string>(type: "text", nullable: true),
                    type = table.Column<string>(type: "text", nullable: true),
                    payload = table.Column<string>(type: "text", nullable: true),
                    isRevoked = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    revocationIndex = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_credential", x => x.jti);
                    table.UniqueConstraint("AK_credential_revocationIndex", x => x.revocationIndex);
                });

            migrationBuilder.CreateTable(
                name: "endpoint",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    Name = table.Column<string>(type: "text", nullable: true),
                    URI = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_endpoint", x => x.ID);
                });

            migrationBuilder.CreateTable(
                name: "resource",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    Name = table.Column<string>(type: "text", nullable: true),
                    URI = table.Column<string>(type: "text", nullable: true),
                    EndpointID = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_resource", x => x.ID);
                    table.ForeignKey(
                        name: "FK_resource_endpoint_EndpointID",
                        column: x => x.EndpointID,
                        principalTable: "endpoint",
                        principalColumn: "ID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "operation",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    Name = table.Column<string>(type: "text", nullable: true),
                    URI = table.Column<string>(type: "text", nullable: true),
                    ResourceID = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_operation", x => x.ID);
                    table.ForeignKey(
                        name: "FK_operation_resource_ResourceID",
                        column: x => x.ResourceID,
                        principalTable: "resource",
                        principalColumn: "ID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "authorization",
                columns: table => new
                {
                    ID = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    ClientID = table.Column<int>(type: "int", nullable: false),
                    OperationID = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authorization", x => x.ID);
                    table.ForeignKey(
                        name: "FK_authorization_client_ClientID",
                        column: x => x.ClientID,
                        principalTable: "client",
                        principalColumn: "ID",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_authorization_operation_OperationID",
                        column: x => x.OperationID,
                        principalTable: "operation",
                        principalColumn: "ID",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_authorization_ClientID",
                table: "authorization",
                column: "ClientID");

            migrationBuilder.CreateIndex(
                name: "IX_authorization_OperationID",
                table: "authorization",
                column: "OperationID");

            migrationBuilder.CreateIndex(
                name: "IX_operation_ResourceID",
                table: "operation",
                column: "ResourceID");

            migrationBuilder.CreateIndex(
                name: "IX_resource_EndpointID",
                table: "resource",
                column: "EndpointID");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authorization");

            migrationBuilder.DropTable(
                name: "credential");

            migrationBuilder.DropTable(
                name: "client");

            migrationBuilder.DropTable(
                name: "operation");

            migrationBuilder.DropTable(
                name: "resource");

            migrationBuilder.DropTable(
                name: "endpoint");
        }
    }
}
