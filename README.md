# E-Store

E-Store is a Flask-based e-commerce platform with a secure, mobile-friendly admin panel. It supports product, category, and customer management, with a focus on a Cash on Delivery (COD) workflow.

## Features

- Secure admin authentication and session management
- Dashboard with overview statistics
- Product management (add, edit, delete, stock tracking, image upload)
- Category management
- Customer management
- Order management system
- Inventory tracking
- Sales analytics and reports
- Responsive admin panel (Bootstrap 5)
- Role-based access control
- Password hashing and security best practices
- User management (create/edit admin users)
- File upload for product images
- Email notifications
- Activity logs

## Setup Instructions

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Create the database:**
   ```bash
   python app.py
   ```
3. **Create an admin user:**
   ```bash
   python create_admin.py
   ```
   Default credentials:
   - Username: admin
   - Password: admin123
   - Email: admin@estore.com
4. **Run the app:**
   ```bash
   python app.py
   ```
5. **Access the admin panel:**
   - Go to `http://localhost:5000/admin/login`

## Usage Guide

- **Add Products:** Admin > Products > Add New Product
- **Manage Categories:** Admin > Categories
- **View Customers:** Admin > Customers
- **Manage Orders:** Admin > Orders (view status, update orders)
- **Track Inventory:** Admin > Products (stock levels, alerts)
- **View Analytics:** Admin > Dashboard (sales reports, statistics)

## Security Recommendations

- Change the default admin password after first login
- Use strong passwords
- Enable HTTPS in production
- Regularly backup your database
- Monitor and log admin actions

## Future Enhancements

- Two-factor authentication for admin accounts
- REST API for mobile app integration
- Customer wishlists and product reviews
- Discount codes and promotions
- Scheduled database backups
- Multi-language support

## License

This project is for educational purposes. Customize and use as needed.


