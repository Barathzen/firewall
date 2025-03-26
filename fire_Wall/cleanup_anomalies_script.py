import sqlite3
import os

def cleanup_network_logs():
    """
    Cleanup network logs database:
    1. Remove all existing network logs
    2. Optionally remove the entire database file
    """
    try:
        # Connect to the database
        conn = sqlite3.connect('firewall_policies.db')
        cursor = conn.cursor()

        # Delete all entries from network_logs table
        cursor.execute("DELETE FROM network_logs")
        
        # Commit changes and close connection
        conn.commit()
        conn.close()

        print("Network logs have been successfully cleared.")

    except sqlite3.Error as e:
        print(f"An error occurred while cleaning up logs: {e}")

def remove_database_file():
    """
    Completely remove the database file
    Use with caution as this deletes all stored data
    """
    try:
        # Path to the database file
        db_path = 'firewall_policies.db'
        
        # Check if file exists before trying to remove
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"Database file {db_path} has been deleted.")
        else:
            print("No database file found.")
    
    except Exception as e:
        print(f"Error removing database file: {e}")

def main():
    print("Cleanup Options:")
    print("1. Clear Network Logs")
    print("2. Remove Entire Database File")
    
    choice = input("Enter your choice (1/2): ").strip()
    
    if choice == '1':
        cleanup_network_logs()
    elif choice == '2':
        # Confirm before deleting
        confirm = input("Are you sure you want to delete the entire database? (yes/no): ").lower()
        if confirm == 'yes':
            remove_database_file()
        else:
            print("Database deletion cancelled.")
    else:
        print("Invalid choice. Please select 1 or 2.")

if __name__ == '__main__':
    main()
