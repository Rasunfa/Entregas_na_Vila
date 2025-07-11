import sqlite3

DB_PATH = 'delivery_system.db'

def fix_paths():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    print('Fixing users table...')
    # First, fix the double uploads issue
    c.execute("UPDATE users SET image_path = REPLACE(image_path, 'uploads/uploads/', 'uploads/') WHERE image_path LIKE 'uploads/uploads/%'")
    # Then fix any remaining static prefixes
    c.execute("UPDATE users SET image_path = REPLACE(image_path, 'static\\', 'uploads/') WHERE image_path LIKE 'static\\%'")
    c.execute("UPDATE users SET image_path = REPLACE(image_path, 'static/', 'uploads/') WHERE image_path LIKE 'static/%'")
    # Convert backslashes to forward slashes
    c.execute("UPDATE users SET image_path = REPLACE(image_path, '\\', '/') WHERE image_path LIKE '%\\%'")
    
    print('Fixing menu_items table...')
    # First, fix the double uploads issue
    c.execute("UPDATE menu_items SET image_path = REPLACE(image_path, 'uploads/uploads/', 'uploads/') WHERE image_path LIKE 'uploads/uploads/%'")
    # Then fix any remaining static prefixes
    c.execute("UPDATE menu_items SET image_path = REPLACE(image_path, 'static\\', 'uploads/') WHERE image_path LIKE 'static\\%'")
    c.execute("UPDATE menu_items SET image_path = REPLACE(image_path, 'static/', 'uploads/') WHERE image_path LIKE 'static/%'")
    # Convert backslashes to forward slashes
    c.execute("UPDATE menu_items SET image_path = REPLACE(image_path, '\\', '/') WHERE image_path LIKE '%\\%'")
    
    conn.commit()
    print('Done!')
    conn.close()

if __name__ == '__main__':
    fix_paths() 