#!/usr/bin/env python3
"""
Script to delete all restaurant accounts and their related data from the delivery system database.
This script will:
1. Delete all menu items associated with restaurants
2. Delete all orders associated with restaurants
3. Delete all restaurant user accounts

WARNING: This will permanently delete all restaurant data!
"""

import sqlite3
import sys
import argparse

def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect('delivery_system.db')
    conn.row_factory = sqlite3.Row
    return conn

def count_restaurants():
    """Count how many restaurant accounts exist."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "restaurant"').fetchone()[0]
    conn.close()
    return count

def list_restaurants():
    """List all restaurant accounts."""
    conn = get_db_connection()
    restaurants = conn.execute('SELECT id, username, restaurant_name FROM users WHERE user_type = "restaurant"').fetchall()
    conn.close()
    return restaurants

def count_related_data():
    """Count related data that will be deleted."""
    conn = get_db_connection()
    
    # Count menu items
    menu_items_count = conn.execute('SELECT COUNT(*) FROM menu_items').fetchone()[0]
    
    # Count orders
    orders_count = conn.execute('SELECT COUNT(*) FROM orders').fetchone()[0]
    
    # Count order items
    order_items_count = conn.execute('SELECT COUNT(*) FROM order_items').fetchone()[0]
    
    conn.close()
    
    return {
        'menu_items': menu_items_count,
        'orders': orders_count,
        'order_items': order_items_count
    }

def delete_restaurants():
    """Delete all restaurant accounts and related data."""
    conn = get_db_connection()
    
    try:
        print("Starting deletion process...")
        
        # First, get all restaurant IDs
        restaurant_ids = [row[0] for row in conn.execute('SELECT id FROM users WHERE user_type = "restaurant"').fetchall()]
        
        if not restaurant_ids:
            print("No restaurant accounts found to delete.")
            return
        
        print(f"Found {len(restaurant_ids)} restaurant(s) to delete.")
        
        # Delete order items first (they reference menu_items and orders)
        print("Deleting order items...")
        conn.execute('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE restaurant_id IN ({}))'.format(
            ','.join('?' * len(restaurant_ids))), restaurant_ids)
        
        # Delete menu items
        print("Deleting menu items...")
        conn.execute('DELETE FROM menu_items WHERE restaurant_id IN ({})'.format(
            ','.join('?' * len(restaurant_ids))), restaurant_ids)
        
        # Delete orders
        print("Deleting orders...")
        conn.execute('DELETE FROM orders WHERE restaurant_id IN ({})'.format(
            ','.join('?' * len(restaurant_ids))), restaurant_ids)
        
        # Finally, delete restaurant users
        print("Deleting restaurant user accounts...")
        conn.execute('DELETE FROM users WHERE user_type = "restaurant"')
        
        # Commit all changes
        conn.commit()
        print("✅ All restaurant accounts and related data have been successfully deleted!")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Error during deletion: {e}")
        raise
    finally:
        conn.close()

def main():
    """Main function to run the deletion script."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Delete all restaurant accounts from the delivery system database.')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt and proceed with deletion')
    args = parser.parse_args()
    
    print("=" * 60)
    print("RESTAURANT ACCOUNT DELETION SCRIPT")
    print("=" * 60)
    print()
    
    # Check if database exists
    try:
        conn = get_db_connection()
        conn.close()
    except Exception as e:
        print(f"❌ Error: Could not connect to database: {e}")
        sys.exit(1)
    
    # Count restaurants
    restaurant_count = count_restaurants()
    if restaurant_count == 0:
        print("No restaurant accounts found in the database.")
        return
    
    # List restaurants
    print(f"Found {restaurant_count} restaurant account(s):")
    restaurants = list_restaurants()
    for restaurant in restaurants:
        name = restaurant['restaurant_name'] or restaurant['username']
        print(f"  - {name} (ID: {restaurant['id']})")
    print()
    
    # Count related data
    data_counts = count_related_data()
    print("Related data that will be deleted:")
    print(f"  - Menu items: {data_counts['menu_items']}")
    print(f"  - Orders: {data_counts['orders']}")
    print(f"  - Order items: {data_counts['order_items']}")
    print()
    
    # Warning
    print("⚠️  WARNING: This action will permanently delete:")
    print("   - All restaurant user accounts")
    print("   - All menu items from restaurants")
    print("   - All orders from restaurants")
    print("   - All order items from restaurant orders")
    print()
    print("This action cannot be undone!")
    print()
    
    # Confirmation
    if args.confirm:
        print("Auto-confirmation enabled. Proceeding with deletion...")
    else:
        while True:
            confirm = input("Are you sure you want to proceed? Type 'YES' to confirm: ").strip()
            if confirm == 'YES':
                break
            elif confirm.lower() in ['no', 'cancel', 'exit', 'quit']:
                print("Operation cancelled.")
                return
            else:
                print("Please type 'YES' to confirm or 'no' to cancel.")
    
    print()
    print("Proceeding with deletion...")
    print()
    
    # Perform deletion
    try:
        delete_restaurants()
        print()
        print("✅ Deletion completed successfully!")
        print()
        print("Remaining data:")
        remaining_data = count_related_data()
        print(f"  - Menu items: {remaining_data['menu_items']}")
        print(f"  - Orders: {remaining_data['orders']}")
        print(f"  - Order items: {remaining_data['order_items']}")
        
    except Exception as e:
        print(f"❌ Deletion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 