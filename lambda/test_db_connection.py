import os
import pymysql

def lambda_handler(event, context):
    host = os.getenv("DB_HOST")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    dbname = os.getenv("DB_NAME")

    try:
        connection = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=dbname,
            connect_timeout=5
        )
        print("Successfully connected to RDS!")
        connection.close()
        return {"status": "success"}

    except Exception as e:
        print(f"Connection failed: {str(e)}")
        return {"status": "failed", "error": str(e)}
