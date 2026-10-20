"""Run a required real MySQL test against an owned, private Unix-socket server.

Keep logs and credentials in the printed mode-0700 directory; never print SQL
containing secrets. Missing binaries/startup/test failures are test failures.
"""
from pathlib import Path
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time


def main():
    os.umask(0o077)
    fixture = Path(tempfile.mkdtemp(prefix="vireo-mysql-test-"))
    print(f"MySQL fixture: {fixture}", flush=True)
    data = fixture / "data"
    data.mkdir(mode=0o700)
    endpoint = fixture / "mysql.sock"
    pidfile = fixture / "mysql.pid"
    root_config = fixture / "root.cnf"
    password_file = fixture / "test.password"
    root_password = secrets.token_hex(32)
    password = secrets.token_hex(32)
    root_config.write_text("[client]\nuser=root\npassword=" + root_password + "\n")
    password_file.write_text(password + "\n")
    environment = dict(os.environ)
    environment["MYSQL_TEST_LOGIN_FILE"] = str(fixture / "absent.mylogin.cnf")
    for key in ("MYSQL_PWD", "MYSQL_HOST", "MYSQL_UNIX_PORT", "MYSQL_TCP_PORT",
                "MYSQL_GROUP_SUFFIX", "MYSQL_HOME"):
        environment.pop(key, None)
    server = None
    configured = False
    outcome = {"fixture": str(fixture), "test_exit": None, "issues": []}

    def sql(statement, authenticated=False, timeout=5):
        args = ["mysql", f"--defaults-file={root_config}" if authenticated else "--no-defaults",
                "--protocol=SOCKET", f"--socket={endpoint}", "--user=root",
                "--connect-timeout=2", "--batch", "--raw", "--skip-column-names"]
        result = subprocess.run(args, input=statement, capture_output=True, text=True,
                                env=environment, timeout=timeout)
        if result.returncode:
            with (fixture / "sql-errors.log").open("a") as log:
                log.write(result.stderr)
            # Avoid echoing credential SQL in client diagnostics.
            raise RuntimeError(f"fixture SQL exit {result.returncode}")
        return result.stdout.strip()

    try:
        with (fixture / "initialize.log").open("x") as log:
            result = subprocess.run(["mysqld", "--no-defaults", "--initialize-insecure",
                                     f"--datadir={data}"], stdout=log, stderr=subprocess.STDOUT,
                                    env=environment, timeout=120)
        if result.returncode:
            raise RuntimeError(f"initialize exit {result.returncode}")
        args = ["mysqld", "--no-defaults", f"--datadir={data}", f"--socket={endpoint}",
                f"--pid-file={pidfile}", f"--log-error={fixture / 'mysql.err'}",
                "--skip-networking", "--mysqlx=OFF", "--local-infile=OFF",
                "--secure-file-priv=NULL", "--skip-log-bin", "--character-set-server=utf8mb4",
                "--default-time-zone=+00:00",
                "--sql-mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
                "--max-connections=16", "--innodb-buffer-pool-size=64M", "--performance-schema=OFF"]
        with (fixture / "server-stdio.log").open("x") as log:
            server = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=environment)
        outcome["server_pid"] = server.pid
        deadline = time.monotonic() + 60
        while True:
            if server.poll() is not None:
                raise RuntimeError("owned server exited before ready")
            if time.monotonic() >= deadline:
                raise TimeoutError("owned server readiness timeout")
            try:
                if sql("SELECT 1") == "1":
                    break
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(0.1)
        sql("ALTER USER 'root'@'localhost' IDENTIFIED BY '" + root_password + "';")
        configured = True
        sql("CREATE DATABASE vireo_connection_test CHARACTER SET utf8mb4;"
            "CREATE USER 'vireo_test'@'localhost' IDENTIFIED BY '" + password + "';"
            "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX ON vireo_connection_test.* "
            "TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "schema":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';",
                authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "download":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_download_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_download_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "gc":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_gc_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_gc_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "replica":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_replica_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_replica_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "manifest":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_manifest_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_manifest_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "upload":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_upload_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_upload_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "audit":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_audit_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_audit_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "nodes":
            sql("GRANT REFERENCES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_nodes_upgrade CHARACTER SET utf8mb4;"
                "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,INDEX,REFERENCES ON "
                "vireo_nodes_upgrade.* TO 'vireo_test'@'localhost';", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "migration":
            sql("GRANT ALL PRIVILEGES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_migration_other CHARACTER SET utf8mb4;"
                "GRANT ALL PRIVILEGES ON vireo_migration_other.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_migration_trigger CHARACTER SET utf8mb4;"
                "GRANT ALL PRIVILEGES ON vireo_migration_trigger.* TO 'vireo_test'@'localhost';"
                "CREATE TABLE vireo_migration_trigger.vireo_schema_migrations("
                "version INT UNSIGNED NOT NULL,checksum BINARY(32) NOT NULL,"
                "state TINYINT UNSIGNED NOT NULL,PRIMARY KEY(version)) ENGINE=InnoDB;"
                # CREATE TRIGGER is not supported by MySQL 8.0 prepared statements.
                # Construct this incompatible shape using the fixture's text client.
                "CREATE TRIGGER vireo_migration_trigger.migration_trigger BEFORE INSERT "
                "ON vireo_migration_trigger.vireo_schema_migrations "
                "FOR EACH ROW SET NEW.state=NEW.state;",
                authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "statement":
            sql("USE vireo_connection_test;"
                "CREATE TABLE statement_values(id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, value TEXT);"
                "CREATE TABLE statement_unique(id BIGINT PRIMARY KEY);"
                "CREATE TABLE statement_reprepare(first INT);"
                "GRANT ALTER,EXECUTE ON vireo_connection_test.* TO 'vireo_test'@'localhost';",
                authenticated=True)
            sql("USE vireo_connection_test;\nDELIMITER //\n"
                "CREATE PROCEDURE statement_multiple() SQL SECURITY DEFINER "
                "BEGIN SELECT 1; SELECT 2; END//\nDELIMITER ;\n", authenticated=True)
        if len(sys.argv) > 2 and sys.argv[2] == "pool":
            sql("USE vireo_connection_test;CREATE TABLE pool_values(id INT PRIMARY KEY);"
                "INSERT INTO pool_values VALUES(1);"
                "GRANT CREATE TEMPORARY TABLES ON vireo_connection_test.* TO 'vireo_test'@'localhost';"
                "CREATE DATABASE vireo_pool_other;"
                "GRANT SELECT ON vireo_pool_other.* TO 'vireo_test'@'localhost';", authenticated=True)
        assert sql("SELECT @@skip_networking,@@local_infile,@@secure_file_priv", True) == "1\t0\tNULL"
        # Verify the owned process has no TCP sockets, including X protocol.
        inodes = set()
        for fd in (Path("/proc") / str(server.pid) / "fd").iterdir():
            try:
                link = os.readlink(fd)
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
            except FileNotFoundError:
                pass
        for family in ("tcp", "tcp6"):
            for line in (Path("/proc") / str(server.pid) / "net" / family).read_text().splitlines()[1:]:
                assert line.split()[9] not in inodes, "owned server has TCP socket"
        result = subprocess.run([sys.argv[1], str(endpoint), "vireo_test", str(password_file),
                                 "vireo_connection_test"], capture_output=True, text=True,
                                env=environment, timeout=90)
        output = result.stdout + result.stderr
        assert password not in output and root_password not in output
        (fixture / "test.log").write_text(output)
        print(output, end="", flush=True)
        outcome["test_exit"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"integration binary exit {result.returncode}")
    except Exception as exc:
        outcome["issues"].append(f"{type(exc).__name__}: {exc}")
    finally:
        if server is not None:
            if server.poll() is None:
                try:
                    sql("SHUTDOWN", authenticated=configured, timeout=8)
                    outcome["sql_shutdown"] = True
                except Exception as exc:
                    outcome["issues"].append(f"shutdown: {type(exc).__name__}")
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                outcome["issues"].append("owned server needed terminate")
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=10)
            outcome["server_exit"] = server.returncode
            outcome["socket_removed"] = not endpoint.exists()
            outcome["pidfile_removed"] = not pidfile.exists()
            outcome["process_reaped"] = not (Path("/proc") / str(server.pid)).exists()
            if server.returncode != 0 or endpoint.exists() or pidfile.exists():
                outcome["issues"].append("owned server cleanup incomplete")
        (fixture / "result.json").write_text(json.dumps(outcome, indent=2) + "\n")
    print(json.dumps(outcome), flush=True)
    return 1 if outcome["issues"] else 0


if __name__ == "__main__":
    sys.exit(main())
