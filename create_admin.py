from app import app, db
from models import Admin
from werkzeug.security import generate_password_hash

def create_admin():
    with app.app_context():
        # Check if admin already exists
        existing_admin = Admin.query.filter_by(username='admin').first()
        if existing_admin:
            print("Admin user already exists!")
            return
        
        # Create default admin user
        admin = Admin(
            username='admin',
            email='admin@estore.com',
            password_hash=generate_password_hash('admin123'),
            first_name='Admin',
            last_name='User',
            role='super_admin',
            is_active=True
        )
        
        db.session.add(admin)
        db.session.commit()
        
        print("Admin user created successfully!")
        print("Username: admin")
        print("Password: admin123")
        print("Email: @adminestore.com")
        print("\nPlease change the password after first login!")

if __name__ == '__main__':
    create_admin() 