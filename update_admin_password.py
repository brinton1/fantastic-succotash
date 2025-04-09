from app import create_app, db
from app import User  # Import the User model from app.py
from werkzeug.security import generate_password_hash  # Import the function to hash the password

# Function to update the admin password
def update_admin_password(new_password):
    # Create the Flask app instance
    app = create_app()

    with app.app_context():
        # Fetch the admin user
        admin_user = User.query.filter_by(username="admin").first()
        
        if admin_user:
            # Hash the new password before updating
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            
            # Update the password for the admin user
            admin_user.password = hashed_password
            db.session.commit()
            print("Admin password updated successfully.")
        else:
            print("Admin user not found.")

# Run the script
if __name__ == "__main__":
    new_password = input("Enter new admin password: ")
    update_admin_password(new_password)
