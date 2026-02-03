-- Create products table
CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    category VARCHAR(100),
    stock INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO products (name, description, price, category, stock) VALUES
('Laptop Pro 15', 'High-performance laptop with 16GB RAM and 512GB SSD', 1299.99, 'Electronics', 25),
('Wireless Mouse', 'Ergonomic wireless mouse with USB receiver', 29.99, 'Accessories', 150),
('Mechanical Keyboard', 'RGB mechanical keyboard with Cherry MX switches', 149.99, 'Accessories', 75),
('USB-C Hub', '7-in-1 USB-C hub with HDMI, USB 3.0, and SD card reader', 49.99, 'Accessories', 200),
('Monitor 27 inch', '4K UHD monitor with IPS panel and HDR support', 449.99, 'Electronics', 30),
('Webcam HD', '1080p HD webcam with built-in microphone', 79.99, 'Electronics', 100),
('External SSD 1TB', 'Portable SSD with USB 3.2 Gen 2 interface', 129.99, 'Storage', 80),
('Headphones Wireless', 'Noise-cancelling wireless headphones with 30h battery', 299.99, 'Audio', 45),
('Desk Lamp LED', 'Adjustable LED desk lamp with USB charging port', 39.99, 'Office', 120),
('Notebook Stand', 'Aluminum laptop stand with adjustable height', 59.99, 'Accessories', 90);

-- Create users table for additional testing
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, email, role) VALUES
('admin', 'admin@example.com', 'admin'),
('john_doe', 'john@example.com', 'user'),
('jane_smith', 'jane@example.com', 'user'),
('bob_wilson', 'bob@example.com', 'moderator');


