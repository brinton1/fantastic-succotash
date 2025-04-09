from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, RegisterForm  # Make sure this line exists
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import db, User, Topic, Comment  # Import db and models from models.py
from better_profanity import profanity  # Replaced profanity-check with better-profanity
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer  # Import sentiment analysis library

# Initialize the extensions here (but don't link them to the app yet)
login_manager = LoginManager()  # Initialize the login manager here
migrate = Migrate()

# Sentiment analyzer initialization
analyzer = SentimentIntensityAnalyzer()

def create_app():
    # Create the Flask app instance
    app = Flask(__name__)

    # Set the configurations for the app
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SECRET_KEY'] = 'mysecretkey'

    # Initialize extensions with the app instance
    db.init_app(app)  # This should only happen once in the app context
    login_manager.init_app(app)  # Initialize the login manager with the app
    migrate.init_app(app, db)

    # Set the login view for Flask-Login
    login_manager.login_view = 'login'

    # User loader function
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Function to check for vulgar content
    def contains_vulgar_content(text):
        # Using better_profanity to detect vulgar content
        return profanity.contains_profanity(text)  # Checks if the text contains profanity

    # Sentiment Analysis Logic
    def analyze_sentiment(text):
        # Check for vulgar content first
        if contains_vulgar_content(text):
            return "This content contains inappropriate language."

        # Proceed with sentiment analysis if no vulgarity is detected
        sentiment_score = analyzer.polarity_scores(text)
        if sentiment_score['compound'] >= 0.05:
            return "Positive"
        elif sentiment_score['compound'] <= -0.05:
            return "Negative"
        else:
            return "Neutral"

    # Route to create an admin user
    @app.route('/create-admin', methods=['GET'])
    def create_admin():
        # Check if admin exists
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            hashed_password = generate_password_hash("admin123", method='pbkdf2:sha256')
            admin_user = User(username="admin", password=hashed_password, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
            return "Admin user created successfully."
        else:
            return "Admin user already exists."

    # Home route
    @app.route('/')
    def home():
        return render_template('home.html')

    # Login route
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()  # Create an instance of the LoginForm
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password, password):
                flash('Login failed. Check your username and/or password.', 'danger')
                return redirect(url_for('login'))
            
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        
        return render_template('login.html', form=form)

    # Register route
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()  # Create an instance of the RegisterForm
        if form.validate_on_submit():
            # Check if the username already exists in the database
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                # If the username already exists, flash a message and don't proceed
                flash('Username already exists!', 'danger')
            else:
                # Check if the email already exists in the database
                user_email = User.query.filter_by(email=form.email.data).first()
                if user_email:
                    flash('Email already exists!', 'danger')
                    return redirect(url_for('register'))

                # Hash the password using pbkdf2:sha256 method
                hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
                new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
                db.session.add(new_user)
                try:
                    db.session.commit()  # Try to commit the changes
                    flash('Registration successful!', 'success')
                    return redirect(url_for('login'))
                except IntegrityError as e:
                    db.session.rollback()  # Rollback the transaction in case of any errors
                    flash(f'An error occurred while saving the user: {str(e)}', 'danger')
                except Exception as e:
                    db.session.rollback()  # Rollback for any other unexpected errors
                    flash(f'An unexpected error occurred: {str(e)}', 'danger')
        return render_template('register.html', form=form)

    # Admin Functionality to create a Topic
    @app.route('/admin/create-topic', methods=['GET', 'POST'])
    @login_required
    def create_topic():
        if not current_user.is_admin:
            flash('You must be an admin to create a topic.', 'danger')
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            
            topic = Topic(title=title, description=description)
            db.session.add(topic)
            db.session.commit()
            flash("Topic Created Successfully", 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('create_topic.html')

    # Admin Functionality to delete a Topic
    @app.route('/admin/delete-topic/<int:topic_id>', methods=['POST'])
    @login_required
    def delete_topic(topic_id):
        if not current_user.is_admin:  # Check if the user is an admin
            flash('You must be an admin to delete a topic.', 'danger')
            return redirect(url_for('home'))  # Redirect to the homepage if not an admin
    
        topic = Topic.query.get_or_404(topic_id)  # Find the topic by its ID
    
        try:
            db.session.delete(topic)  # Delete the topic
            db.session.commit()  # Commit the deletion to the database
            flash('Topic deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()  # Rollback in case of any error
            flash('Error deleting topic. Please try again.', 'danger')
    
        return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard after deletion

    # Route to submit comments with sentiment analysis
    @app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
    @login_required
    def topic_page(topic_id):
        topic = Topic.query.get_or_404(topic_id)
        
        if request.method == 'POST':
            content = request.form['content']
            sentiment = analyze_sentiment(content)
            
            # Ensure the current_user's ID is set for the user_id field in the comment
            comment = Comment(content=content, sentiment=sentiment, topic_id=topic.id, user_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('topic_page', topic_id=topic.id))
        
        comments = Comment.query.filter_by(topic_id=topic_id).all()
        return render_template('topic_page.html', topic=topic, comments=comments)

    # Admin Dashboard - Fetch Comments for Sentiment Analysis
    @app.route('/admin/dashboard')
    @login_required
    def admin_dashboard():
        if not current_user.is_admin:
            flash('You must be an admin to access the dashboard.', 'danger')
            return redirect(url_for('home'))

        topics = Topic.query.all()  # Fetch all topics
        sentiments = {"positive": 0, "negative": 0, "neutral": 0}
        
        # Count the sentiment of comments for each topic
        for topic in topics:
            for comment in topic.comments:
                sentiments[comment.sentiment.lower()] += 1
        
        # Prepare Data for Pie Chart
        sentiment_data = {
            'labels': ['Positive', 'Negative', 'Neutral'],
            'values': [sentiments['positive'], sentiments['negative'], sentiments['neutral']]
        }
        
        return render_template('admin_dashboard.html', sentiment_data=sentiment_data, topics=topics)

    # Route to display topics to users (added route)
    @app.route('/topics')
    @login_required
    def topics():
        topics = Topic.query.all()  # Fetch all topics from the database
        return render_template('topics.html', topics=topics)

    # User logout route
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('home'))

    # Route to delete a comment
    @app.route('/delete-comment/<int:comment_id>', methods=['POST'])
    @login_required
    def delete_comment(comment_id):
        comment = Comment.query.get_or_404(comment_id)  # Get the comment by its ID

        # Check if the current user is the author of the comment or an admin
        if comment.user_id == current_user.id or current_user.is_admin:
            try:
                db.session.delete(comment)  # Delete the comment
                db.session.commit()  # Commit the change to the database
                flash('Comment deleted successfully.', 'success')
            except Exception as e:
                db.session.rollback()  # Rollback in case of any error
                flash(f'Error deleting comment: {str(e)}', 'danger')
        else:
            flash('You are not authorized to delete this comment.', 'danger')
        
        # Redirect back to the topic page
        return redirect(url_for('topic_page', topic_id=comment.topic_id))

    return app

# Initialize the database and create tables within app context
app = create_app()

# Create the database tables (if they don't exist already)
with app.app_context():
    db.create_all()
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

