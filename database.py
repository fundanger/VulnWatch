import configparser

import mysql.connector

CONFIG = configparser.ConfigParser()
CONFIG.read("config.ini")


def create_tables(service_name):
    try:
        print("Creating table for " + str(service_name))
        connection = mysql.connector.connect(
            user=CONFIG["DATABASE"]["username"],
            password=CONFIG["DATABASE"]["password"],
            host=CONFIG["DATABASE"]["host"],
            database=CONFIG["DATABASE"]["database"],
        )
        cursor = connection.cursor()
        tableQuery = (
            "CREATE TABLE IF NOT EXISTS "
            + service_name
            + """(cve_id VARCHAR(255) NOT NULL PRIMARY KEY,
                      publish_date DATE,
                      last_modified DATE,
                      description TEXT);"""
        )
        cursor.execute(tableQuery)
        connection.commit()
    except mysql.connector.Error as error:
        print("An error occurred in process CreateTables:", error)
    finally:
        connection.close()


def insert_data(table, CVE, publish_date, last_modified, description, email):
    try:
        connection = mysql.connector.connect(
            user=CONFIG["DATABASE"]["username"],
            password=CONFIG["DATABASE"]["password"],
            host=CONFIG["DATABASE"]["host"],
            database=CONFIG["DATABASE"]["database"],
        )
        cursor = connection.cursor()
        insertQuery = (
            "INSERT IGNORE INTO "
            + table
            + " (cve_id, publish_date, last_modified, description)"
            + " VALUES"
            + " (%s, %s, %s, %s);"
        )
        cursor.execute(insertQuery, (CVE, publish_date, last_modified, description))
        connection.commit()
        if cursor.rowcount > 0:
            email += "Service: " + table
            email += "\nCVE-" + CVE + "\n"
            email += "publish_date: " + publish_date + "\n"
            email += "last_modified: " + last_modified + "\n"
            email += "description: " + description + "\n \n"
        else:
            print("No entry added.")
    except mysql.connector.Error as error:
        print("An error occurred in process insertData:", error)
    finally:
        connection.close()
        return str(email)
