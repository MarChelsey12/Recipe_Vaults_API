from flask import Flask, make_response, request, g, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime as dt, timedelta
import secrets
import os


class Config():
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS")


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()


@basic_auth.verify_password
def verify_password(email, password):
    u = User.query.filter_by(email=email.lower()).first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)


@token_auth.verify_token
def verify_token(token):
    u = User.check_token(token) if token else None
    g.current_user = u
    return g.current_user or None

    ##############
    #   MODELS   #
    ##############


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    email = db.Column(db.String, index=True, unique=True)
    password = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    updated_on = db.Column(db.DateTime, onupdate=dt.utcnow)
    token = db.Column(db.String, index=True, unique=True)
    token_exp = db.Column(db.DateTime)
    collections = db.relationship(
        'Collection', cascade='all, delete-orphan', backref='owner', lazy='dynamic')
    recipes = db.relationship(
        'Recipe', cascade='all, delete-orphan', backref='creator', lazy="dynamic")

    def __repr__(self):
        return f'<{self.id}|{self.username}>'

    def get_token(self, exp=86400):
        current_time = dt.utcnow()
        if self.token and self.token_exp > current_time + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_urlsafe(32)
        self.token_exp = current_time + timedelta(seconds=exp)
        self.save()
        return self.token

    def revoke_token(self):
        self.token_exp = dt.utcnow() - timedelta(seconds=61)

    @staticmethod
    def check_token(token):
        u = User.query.filter_by(token=token).first()
        if not u or u.token_exp < dt.utcnow():
            return None
        return u

    def hash_password(self, original_password):
        return generate_password_hash(original_password)

    def check_hashed_password(self, login_password):
        return check_password_hash(self.password, login_password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    # creates NEW user from dictonary
    def from_dict(self, data):
        for field in ["username", "email", "password"]:
            if field in data:
                if field == "password":
                    setattr(self, field, self.hash_password(data[field]))
                else:
                    setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_on": self.created_on,
            "updated_on": self.updated_on,
            "token": self.token
        }

    def register(self, data):
        self.username = data['username']
        self.email = data['email']
        self.password = self.hash_password(data['password'])


class Collection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    updated_on = db.Column(db.DateTime, onupdate=dt.utcnow)
    recipes = db.relationship(
        'Recipe', cascade='all, delete-orphan', backref='group', lazy="dynamic")

    def __repr__(self):
        return f'<Collection: {self.id} | {self.created_by}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['name', 'created_by']:
            setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "created_by": self.created_by,
            "created_on": self.created_on,
            "updated_on": self.updated_on,

        }


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String)
    item_list = db.relationship(
        'Ingredient', cascade='all, delete-orphan', backref="items", lazy="dynamic")
    directions = db.Column(db.Text)
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    updated_on = db.Column(db.DateTime, onupdate=dt.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    collection_id = db.Column(db.Integer, db.ForeignKey("collection.id"))

    def __repr__(self):
        return f'<Recipe: {self.id} | {self.title}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ['title', 'item_list', 'directions', 'collection_id']:
            if field == 'item_list':
                for item in data['item_list']:
                    new_item = Ingredient()
                    new_item.from_dict(item)
                    new_item.save()
                    self.item_list.append(new_item)
            else:
                setattr(self, field, data[field])

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'item_list': [recipe.to_dict() for recipe in self.recipes],
            'directions': self.directions,
            'created_on': self.created_on,
            'updated_on': self.updated_on,
            'collection_id': self.collection_id,
            'collection_name': self.group.name
        }


class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        for field in ["item"]:
            if field in data:
                setattr(self, field, data[field])

    def to_dict(self):
        return {
            "id": self.id,
            "item": self.item,
            "recipe_id": self.recipe_id
        }

    ##############
    # API ROUTES #
    ##############
'''
    Responses:
    200 : Everything went well
    401 : Invalid Token, or invalid Username/Password,
    403 : User not authorized for action
    404 : Resource not found
    500 : Server Side Error
'''
    ### USER ROUTES ###
@app.get('/login')
@basic_auth.login_required()
def login():
    '''
        BasicAuth: base64encoded string=> email:password
        Authorization: Basic base64encoded_string
        returns user information including token
    '''
    g.current_user.get_token()
    return make_response(g.current_user.to_dict(), 200)


@app.post('/user')
def post_user():
    '''
        No Auth
        creates a new user.
        expected payload:
        {
            "username" : STRING,
            "email" : STRING,
            "password" : STRING,

        }
    '''
    data = request.get_json()
    if User.query.filter_by(email=data.get('email')).first():
        abort(422)
    new_user = User()
    new_user.register(data)
    new_user.save()
    return make_response("success", 200)


@app.put('/user')
@token_auth.login_required()
def put_user():
    '''
        Changes the information fro the user that has the token
        TokenAuth: Bearer TOKEN
        expected payload (does not need to include all key value pairsAny omitted values will remain unchanged):
        {
            "username" : STRING,
            "email" : STRING,
            "password" : STRING,
        }
    '''
    data = request.get_json()
    g.current_user.from_dict(data)
    db.session.commit()
    return make_response("success", 200)


@app.delete('/user')
@token_auth.login_required()
def delete_user():
    '''
        Can only be used by the user with <user_id>
        TokenAuth: Bearer TOKEN
        Will delete User accesing the endpoint
    '''
    g.current_user.delete()
    return make_response("success", 200)

    ### COLLECTION ROUTES ###
@app.get('/collection')
@token_auth.login_required()
def get_collections():
    '''
        returns All collections
    '''
    return make_response({"Collections": [collection.to_dict() for collection in Collection.query.all()]}, 200)


@app.post('/collection')
@token_auth.login_required()
def post_collection():
    '''
        expected payload:
        {
            "name" : STRING,            
        }
    '''
    data = request.get_json().get("name")
    new_group = Collection(name=data)
    new_group.save()
    return make_response("success", 200)


@app.put('/collection/<int:id>')
@token_auth.login_required()
def put_collection(id):
    '''
        expected payload:
        {
            "name" : STRING,           
        }
    '''
    data = request.get_json().get("name")
    edit_group = Collection.query.get(id)
    if not edit_group:
        abort(404)
    edit_group.name = data
    edit_group.save()
    return make_response("success", 200)


@app.delete('/collection/<int:id>')
@token_auth.login_required()
def delete_collection():
    '''
        Can only be used by the user with <user_id>
        TokenAuth: Bearer TOKEN
        Will delete User accesing the endpoint
    '''
    group = Collection.query.get(id)
    if not group:
        abort(404)
    group.delete()
    return make_response("success", 200)

    ### RECIPE ROUTES ###
@app.get('/recipe')
@token_auth.login_required()
def get_recipes():
    '''
        returns All Recipe information
    '''
    card = Recipe.query.get(id)
    user = g.current_user
    if card.user_id == user.id:
        return make_response({"recipes":[recipe.to_dict() for recipe in Recipe.query.all()]}, 200)

@app.get('/recipe/<int:id>')
@token_auth.login_required()
def get_recipe(id):
    '''
        returns info for the recipe with the id:id
    '''
    card = Recipe.query.get(id)
    user = g.current_user
    if card.user_id == user.id:
        return make_response(Recipe.query.filter_by(id=id).first().to_dict(), 200)

@app.post('/recipe')
@token_auth.login_required()
def post_recipe():
    '''
        Creates a recipe
        TokenAuth: Bearer TOKEN
        expected payload:
        {
            title : STRING,
            item_list : DICT,
            directions : TEXT,
            collection_id : INT,
            
        }
    '''
    data = request.get_json()
    new_recipe = Recipe()
    new_recipe.new(data)
    new_recipe.save()
    return make_response("success",200)

@app.put('/recipe')
@token_auth.login_required()
def put_recipe():
    '''
        Changes the information of the recipe from the user that created it
        TokenAuth: Bearer TOKEN
        expected payload (does not need to include all key value pairsAny omitted values will remain unchanged):
        {
            "title" : STRING,
            item_list : DICT,
            directions : TEXT,
            "collection_id" : INT,
        }
    '''
    data = request.get_json()
    edit_recipe = Recipe.query.get(data['id'])
    if not edit_recipe:
        abort(404)
    if not edit_recipe.creator.id == g.current_user.id:
        abort(403)
    edit_recipe.from_dict(data)
    edit_recipe.save()
    return make_response("success",200)

@app.delete('/recipe/<int:id>')
@token_auth.login_required()
def delete_recipe(id):
    card = Recipe.query.get(id)
    user = g.current_user
    if not card:
        abort(404)
    if not card.user_id == user.id:
        abort(403)    
    card.delete()
    return make_response("success",200)

if __name__ == "__main__":
    app.run(debug=True)
