# app.py
from datetime import datetime
from functools import wraps
# from flask_jwt_extended import JWTManager
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'  # Database file will be created in the project folder
db = SQLAlchemy(app)


def user_auth_context_processor():
    user_is_authenticated = 'user_id' in session
    return {'user_is_authenticated': user_is_authenticated}


app.context_processor(user_auth_context_processor)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


recipe_ingredient_association = db.Table(
    'recipe_ingredient_association',
    db.Column('recipe_id', db.Integer, db.ForeignKey('recipe.id')),
    db.Column('ingredient_id', db.Integer, db.ForeignKey('ingredient.id'))
)


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    instructions = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0.0)
    num_ratings = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ingredients = db.relationship('Ingredient', secondary=recipe_ingredient_association, back_populates='recipes')
    comments = relationship('Comment')
    user = db.relationship('User')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    text = db.Column(db.Text, nullable=False)
    user = db.relationship('User')


class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text, nullable=False)
    recipes = db.relationship('Recipe', secondary=recipe_ingredient_association, back_populates='ingredients')


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    image = db.Column(db.Text, default="https://m.media-amazon.com/images/I/517gfFg6I6L._AC_.jpg")
    description = db.Column(db.Text, default="...")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return self.name


with app.app_context():
    db.create_all()


# @app.route('/signup', methods=['POST'])
# def signup():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#
#     if not username or not password:
#         return jsonify({'message': 'Username and password are required'}), 400
#
#     if User.query.filter_by(username=username).first():
#         return jsonify({'message': 'Username already exists'}), 400
#
#     new_user = User(username=username, password=generate_password_hash(password, method='sha256'))
#     db.session.add(new_user)
#     db.session.commit()
#     return jsonify({'message': 'User created successfully'}), 201


# Endpoint to authenticate a user
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username')
#     password = data.get('password')
#
#     user = User.query.filter_by(username=username).first()
#
#     if not user:
#         return jsonify({'message': 'User not found'}), 401
#
#     if not check_password_hash(user.password, password):
#         return jsonify({'message': 'Incorrect password'}), 401
#
#     return jsonify({'message': 'Login successful'}), 200

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not user_is_authenticated1():
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def user_is_authenticated1():
    return 'user_id' in session


def get_current_user():
    user_id = session.get('user_id')
    if user_id is not None:
        user = User.query.get(user_id)  # Replace User with your actual User model
        return user
    return None


@app.route('/')
def index():
    session.pop('_flashes', None)
    recipes = Recipe.query.all()  # Query all recipes from the database
    return render_template('index.html', recipes=recipes)


# USER routes
@app.route("/users")
def user_list():
    users = db.session.execute(db.select(User).order_by(User.username)).scalars()
    return render_template("user/list.html", users=users)


@app.route("/users/create", methods=["GET", "POST"])
def user_create():
    if request.method == "POST":
        existing_user = User.query.filter_by(username=request.form["username"]).first()

        if existing_user:
            flash("Username already exists. Please choose a different username.", "error")
            return redirect(url_for("user_create"))
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        user = User(
            username=request.form["username"],
            password=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("user_detail", user_id=user.id))
    session['isLoggedin'] = True

    return render_template("user/create.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if a user with the provided username exists
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # Password is correct, log the user in
            session["user_id"] = user.id
            session['isLoggedin'] = True
            flash("Login successful!", "success")
            return redirect(url_for("user_detail", id=user.id))
        else:
            # Invalid username or password
            flash("Invalid username or password. Please try again.", "error")

    return render_template("user/login.html")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # get value from get request and clear sessions values
    if request.method == 'GET':
        session.pop('user_id', None)
        session['isLoggedin'] = False
        session.pop('_flashes', None)
        # success message to users
        flash("You are logged out", 'success')
    return redirect(url_for('index'))


@app.route("/user/info")
@login_required
def user_detail():
    current_user = get_current_user()
    if current_user:
        recipes = Recipe.query.filter_by(user_id=current_user.id).all()
        return render_template("user/detail.html", user=current_user, user_is_authenticated=user_is_authenticated1,
                               recipes=recipes)
    else:
        return render_template('404.html')


@app.errorhandler(404)
def page_not_found(error):
    # 404 error is redirected to 404.html
    return render_template('404.html')


@app.route("/user/<int:id>/delete", methods=["GET", "POST"])
@login_required
def user_delete(id):
    user = db.get_or_404(User, id)

    if request.method == "POST":
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for("user_list"))

    return render_template("user/delete.html", user=user)


# RECIPE routes

@app.route('/create_recipe', methods=['GET', 'POST'])
@login_required
def create_recipe():
    ingredients = Ingredient.query.all()
    if request.method == 'POST':
        title = request.form.get('title')
        image_url = request.form.get('image_url')
        instructions = request.form.get('instructions')
        selected_ingredient_ids = request.form.getlist('ingredient_ids')  # Get a list of selected ingredient IDs

        ingredients_selected = Ingredient.query.filter(Ingredient.id.in_(selected_ingredient_ids)).all()
        user = get_current_user()
        user_id = user.id if user else None

        recipe = Recipe(
            title=title,
            image_url=image_url,
            instructions=instructions,
            ingredients=ingredients_selected,
            user_id=user_id
        )

        db.session.add(recipe)
        db.session.commit()

        flash('Recipe created successfully', 'success')
        return redirect(url_for('index'))

    return render_template('recipe/create.html', ingredients=ingredients)


# Read a recipe
@app.route('/recipe/<int:id>')
def detail_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    ingredients = list(recipe.ingredients)
    user = get_current_user()
    user_id = user.id if user else None
    if not ingredients:
        return render_template('404.html')
    return render_template('recipe/detail.html', recipe=recipe, ingredients=ingredients, user_id=user_id)


# Update a recipe
@app.route('/update_recipe/<int:id>', methods=['GET', 'POST'])
@login_required
def update_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    ingredients = Ingredient.query.all()

    if request.method == 'POST':
        title = request.form.get('title')
        image_url = request.form.get('image_url')
        instructions = request.form.get('instructions')
        selected_ingredient_ids = request.form.getlist('ingredient_ids')

        ingredients_selected = Ingredient.query.filter(Ingredient.id.in_(selected_ingredient_ids)).all()

        # Fetch the recipe and update its fields
        recipe = Recipe.query.get_or_404(id)
        recipe.title = title
        recipe.image_url = image_url
        recipe.instructions = instructions

        recipe.ingredients.clear()
        recipe.ingredients.extend(ingredients_selected)
        user = get_current_user()
        user_id = user.id if user else None
        recipe.user_id = user_id

        # Commit the changes
        db.session.commit()

        # Flash message and redirect
        flash('Recipe updated successfully', 'success')
        return redirect(url_for('detail_recipe', id=recipe.id))

    return render_template('recipe/update.html', recipe=recipe, ingredients=ingredients)


# Delete a recipe
@app.route('/recipe/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_recipe(id):
    recipe = Recipe.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(recipe)
        db.session.commit()
        flash('Recipe deleted successfully', 'success')
        return redirect(url_for('index'))


@app.route('/recipe/<int:id>/add_comment', methods=['POST'])
def add_comment(id):
    recipe = Recipe.query.get(id)
    text = request.form.get('comment')

    if text:
        user = get_current_user()
        user_id = user.id if user else None

        new_comment = Comment(text=text, recipe_id=recipe.id, user_id=user_id)
        db.session.add(new_comment)
        db.session.commit()

    return redirect(url_for('detail_recipe', id=id))


@app.route('/comment/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(id):
    comment = Comment.query.get_or_404(id)

    if request.method == 'POST':
        comment.text = request.form.get('text')
        db.session.commit()
        return redirect(url_for('detail_recipe', id=comment.recipe.id))

    return render_template('comments/edit.html', comment=comment)


@app.route('/comment/<int:id>/delete', methods=['POST'])
@login_required
def delete_comment(id):
    comment = Comment.query.get_or_404(id)
    recipe_id = comment.recipe.id

    db.session.delete(comment)
    db.session.commit()

    return redirect(url_for('detail_recipe', id=recipe_id))


@app.route('/create-ingredient', methods=['GET', 'POST'])
@app.route('/create-ingredient/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def create_ingredient(recipe_id=None):
    if request.method == 'POST':
        title = request.form.get('title')
        image_url = request.form.get('image_url')
        description = request.form.get('description')

        if title and description:
            new_ingredient = Ingredient(title=title, image_url=image_url, description=description)
            db.session.add(new_ingredient)
            db.session.commit()

            if recipe_id:
                return redirect(url_for('update_recipe', id=recipe_id))
            else:
                return redirect(url_for('create_recipe'))

    return render_template('ingredients/create.html', recipe_id=recipe_id)


@app.route('/ingredient/<int:ingredient_id>')
@login_required
def read_ingredient(ingredient_id):
    ingredient = Ingredient.query.get_or_404(ingredient_id)
    return render_template('ingredients/detail.html', ingredient=ingredient)


@app.route('/ingredient/<int:ingredient_id>/update', methods=['GET', 'POST'])
@login_required
def update_ingredient(ingredient_id):
    ingredient = Ingredient.query.get_or_404(ingredient_id)

    if request.method == 'POST':
        ingredient.title = request.form.get('title')
        ingredient.image_url = request.form.get('image_url')
        ingredient.description = request.form.get('description')

        db.session.commit()

        return redirect(url_for('read_ingredient', ingredient_id=ingredient_id))

    return render_template('ingredients/update.html', ingredient=ingredient)


@app.route('/ingredient/<int:ingredient_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_ingredient(ingredient_id):
    ingredient = Ingredient.query.get_or_404(ingredient_id)

    # Check if the ingredient is used in any recipe
    used_in_recipes = Recipe.query.filter(Recipe.ingredients.any(id=ingredient_id)).all()

    if request.method == 'POST':
        if used_in_recipes:
            flash('Ingredient is used in recipes. Cannot delete.', 'error')
        else:
            db.session.delete(ingredient)
            db.session.commit()
            flash('Ingredient deleted successfully', 'success')
        return redirect(url_for('index'))

    return render_template('ingredients/delete.html', ingredient=ingredient, used_in_recipes=used_in_recipes)
# @app.route('/recipes')
# def recipe_list():
#     recipes = Recipe.query.all()  # Query all recipes from the database
#     return render_template('index.html', recipes=recipes)


if __name__ == '__main__':
    app.run()
# @app.route('/signup_user', methods=['POST'])
# def signup_user():
#     username = request.form.get('signupUsername').lower()
#     user = User.query.filter_by(username=username).first()
#
#     if user is None:
#         new_user = User(
#             username=username,
#             hashed_password=generate_password_hash(request.form.get('signupPassword'), method='sha256'),
#             firstname=request.form.get('firstName'),
#             lastname=request.form.get('lastName')
#         )
#
#         db.session.add(new_user)
#         db.session.commit()
#
#         return "success"
#     else:
#         return "fail"
#
# # User Login
# @app.route('/login_user', methods=['POST'])
# def login_user():
#     username = request.form.get('loginUsername').lower()
#     user = User.query.filter_by(username=username).first()
#
#     if user:
#         if check_password_hash(user.hashed_password, request.form.get('loginPassword')):
#             session['username'] = user.username
#             session['userid'] = user.id
#             session['isLoggedin'] = True
#
#             message = "Welcome back, " + user.username + ". You will be redirected to your MyRecipes page."
#             response = {
#                 "username": user.username,
#                 "_id": user.id,
#                 "message": message
#             }
#             return jsonify(response)
#         else:
#             return "1"  # Wrong password
#     else:
#         return "2"  # No user by that username
#
# if __name__ == '__main__':
#     app.run(debug=True)
