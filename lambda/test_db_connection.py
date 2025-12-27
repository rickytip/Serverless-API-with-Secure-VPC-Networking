import os
import json
import boto3
import pymysql


secrets_client = boto3.client("secretsmanager")


def get_db_secret() -> dict:
    """
    Fetch and parse the DB credentials JSON from AWS Secrets Manager.
    Expects env var DB_SECRET to be set to the secret ARN (or name).
    """
    secret_id = os.environ.get("db_secret")
    if not secret_id:
        raise ValueError("Missing required environment variable: db_secret")

    resp = secrets_client.get_secret_value(SecretId=secret_id)

    # Secrets Manager typically returns SecretString for JSON secrets
    secret_str = resp.get("SecretString")
    if secret_str:
        return json.loads(secret_str)

    # Fallback (rare): SecretBinary
    secret_bin = resp.get("SecretBinary")
    if secret_bin:
        # SecretBinary is bytes; decode then parse
        return json.loads(secret_bin.decode("utf-8"))

    raise ValueError("Secret value had neither SecretString nor SecretBinary")


def lambda_handler(event, context):
    print("Starting handler")
    """
    Expected secret JSON keys (common pattern):
      - host
      - port (optional; default 3306)
      - username
      - password
      - dbname (or database)

    Example secret JSON:
    {
      "host": "mydb.abc123xyz.us-east-2.rds.amazonaws.com",
      "port": 3306,
      "username": "admin",
      "password": "supersecret",
      "dbname": "mydb"
    }
    """
    print("Fetching DB secret")
    secret = get_db_secret()

    host = secret["host"]
    port = int(secret.get("port", 3306))
    user = secret.get("username") or secret.get("user")
    password = secret["password"]
    dbname = secret.get("dbname") or secret.get("database")

    if not user:
        raise ValueError("Secret JSON missing 'username' (or 'user')")
    if not dbname:
        raise ValueError("Secret JSON missing 'dbname' (or 'database')")
    print("Connecting to DB")
    conn = None
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=dbname,
            port=port,
            connect_timeout=90,
            read_timeout=60,
            write_timeout=60,
            cursorclass=pymysql.cursors.DictCursor,
        )
        print("Connected to DB successfully")
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ok;")
            row = cur.fetchone()

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Connected to DB successfully",
                    "test_query": row,
                }
            ),
        }

    except Exception as e:
        # This will show up in CloudWatch logs
        print(f"ERROR connecting/querying DB: {repr(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "DB connection failed", "error": str(e)}),
        }

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

