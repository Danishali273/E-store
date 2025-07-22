from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class Customer(UserMixin, db.Model):
    __tablename__ = 'customers'
    customer_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20))
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255), unique=True)
    token_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    shopping_carts = db.relationship('ShoppingCart', backref='customer', lazy='dynamic', cascade='all, delete-orphan')
    orders = db.relationship('Order', backref='customer', lazy='dynamic')
    
    def __init__(self, first_name, last_name, email, password_hash, phone_number=None, is_active=True, email_verified=False):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password_hash = password_hash
        self.phone_number = phone_number
        self.is_active = is_active
        self.email_verified = email_verified

    def get_id(self):
        return str(self.customer_id)

class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), default='admin')  # admin, super_admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __init__(self, username, email, password_hash, first_name, last_name, role='admin', is_active=True):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.first_name = first_name
        self.last_name = last_name
        self.role = role
        self.is_active = is_active

    def get_id(self):
        return str(self.admin_id)

class Product(db.Model):
    __tablename__ = 'products'
    product_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    sku = db.Column(db.String(100), unique=True, nullable=False)
    stock_quantity = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(255)) # Main image for quick access
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'))
    
    # Relationships
    category = db.relationship('Category', backref=db.backref('products', lazy='dynamic'))

    def __init__(self, name, description, price, sku, stock_quantity=0, image_url=None, is_active=True):
        self.name = name
        self.description = description
        self.price = price
        self.sku = sku
        self.stock_quantity = stock_quantity
        self.image_url = image_url
        self.is_active = is_active

class ProductImage(db.Model):
    __tablename__ = 'product_images'
    image_id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id', ondelete='CASCADE'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    is_main = db.Column(db.Boolean, default=False)

    product = db.relationship('Product', backref=db.backref('images', cascade='all, delete-orphan'))

    def __init__(self, product_id, image_url, is_main=False):
        self.product_id = product_id
        self.image_url = image_url
        self.is_main = is_main

class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)

    def __init__(self, name, description=None):
        self.name = name
        self.description = description

class ShoppingCart(db.Model):
    __tablename__ = 'shopping_carts'
    cart_id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id', ondelete='CASCADE'), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    items = db.relationship('CartItem', backref='cart', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, customer_id):
        self.customer_id = customer_id

class CartItem(db.Model):
    __tablename__ = 'cart_items'
    cart_item_id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('shopping_carts.cart_id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    # Relationships
    product = db.relationship('Product')

    def __init__(self, cart_id, product_id, quantity):
        self.cart_id = cart_id
        self.product_id = product_id
        self.quantity = quantity

class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, processing, shipped, delivered, cancelled
    
    # COD and Shipping Details (filled from COD form)
    recipient_name = db.Column(db.String(100), nullable=False)
    recipient_phone = db.Column(db.String(20), nullable=False)
    recipient_email = db.Column(db.String(100))
    shipping_address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    postal_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), default='Pakistan')
    
    # Payment is always COD
    payment_method = db.Column(db.String(50), default='COD')
    payment_status = db.Column(db.String(20), default='pending')  # pending, paid
    
    # Optional fields
    delivery_notes = db.Column(db.Text)  # Special delivery instructions
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    items = db.relationship('OrderItem', backref='order', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, customer_id, order_number, total_amount, recipient_name, recipient_phone, 
                 shipping_address, city, state, postal_code, recipient_email=None, 
                 country='Pakistan', delivery_notes=None, status='pending'):
        self.customer_id = customer_id
        self.order_number = order_number
        self.total_amount = total_amount
        self.recipient_name = recipient_name
        self.recipient_phone = recipient_phone
        self.recipient_email = recipient_email
        self.shipping_address = shipping_address
        self.city = city
        self.state = state
        self.postal_code = postal_code
        self.country = country
        self.delivery_notes = delivery_notes
        self.status = status
        self.payment_method = 'COD'
        self.payment_status = 'pending'

    def get_id(self):
        return str(self.order_id)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    order_item_id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.order_id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)  # Price per unit at time of order
    
    # Relationships
    product = db.relationship('Product')
    
    def __init__(self, order_id, product_id, quantity, price):
        self.order_id = order_id
        self.product_id = product_id
        self.quantity = quantity
        self.price = price
    
    @property
    def total_price(self):
        """Calculate total price for this item"""
        return float(self.price) * self.quantity

    def get_id(self):
        return str(self.order_item_id)