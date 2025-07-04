from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    user_type = SelectField('Tipo de Conta', choices=[('client', 'Cliente'), ('restaurant', 'Restaurante')])
    location = StringField('Localização')
    submit = SubmitField('Registrar')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class MenuForm(FlaskForm):
    name = StringField('Nome do Prato', validators=[DataRequired(), Length(max=150)])
    description = TextAreaField('Descrição', validators=[DataRequired()])
    price = StringField('Preço', validators=[DataRequired()])
    submit = SubmitField('Salvar')

class OrderForm(FlaskForm):
    menu_id = SelectField('Prato', coerce=int, validators=[DataRequired()])
    notes = TextAreaField('Notas', validators=[Length(max=500)])
    submit = SubmitField('Fazer Pedido')
