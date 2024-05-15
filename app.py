import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
from helpers import apology, login_required, lookup, usd


# api_token = pk_fd206901bf14485da75decbbd1b6ca33

app = Flask(__name__)

app.jinja_env.filters["usd"] = usd
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Changes user password"""
    if request.method == "GET":
        user_id = session["user_id"]
        username = db.execute("SELECT username FROM users WHERE id = ?", user_id)
        name = username[0]["username"]
        return render_template("settings.html", username = name)
    else:
        password = request.form.get("curr_password")
        new_pass = request.form.get("confirmation")

        if password == new_pass:
            return apology("No chamnges made!")

        try:
            user_id = session["user_id"]
            curr_pass = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

            if password == curr_pass:
                return apology("No chamnges made!")

            if not check_password_hash(curr_pass[0]["hash"], password):
                return apology("wrong password", 403)

            hashed_password = generate_password_hash(new_pass)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, user_id)

            flash("Password succesfully updated")
            return redirect("/")
        except:
            return apology("Something went wrong")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions = db.execute("SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    portfolio = []
    total_value = cash

    for transaction in transactions:
        stock = lookup(transaction["symbol"])
        if stock:
            price = float(stock["price"])
            shares = int(transaction["shares"])
            total = shares * price
            portfolio.append({
                "symbol": transaction["symbol"],
                "shares": shares,
                "price": price,
                "total": total
            })
            total_value += total

    cash_formatted = usd(cash)
    total_value_formatted = usd(total_value)

    # Format prices and totals in the portfolio
    for stock in portfolio:
        stock["price"] = usd(stock["price"])
        stock["total"] = usd(stock["total"])

    return render_template("index.html", portfolio=portfolio, cash=cash_formatted, total_value=total_value_formatted)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Invalid number of shares")
        if not symbol:
            return apology("No symbol entered")
        if shares <= 0:
            return apology("Shares not allowed")


        quote = lookup(symbol)
        if quote is None:
            return apology("Symbol doesn't exist")

        transaction_value = shares * quote["price"]

        user_id = session["user_id"]
        user_balance = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_balance[0]["cash"]

        if user_cash < transaction_value:
            return apology("Not enough money")

        update_cash = user_cash - transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", update_cash, user_id)

        date = datetime.datetime.now()
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, opType, date) VALUES (?, ?, ?, ?, ?, ?)", user_id, symbol, shares, quote["price"], "BUY", date)

        flash("Stock successfully bought!")

        return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, shares, price, date, opType FROM transactions WHERE user_id = ? ORDER BY date DESC", user_id)
    return render_template("history.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    session.clear()

    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("No symbol entered")

        try:
            stock = lookup(symbol)

            if not stock:
                return apology("Symbol doesn't exist")
            return render_template("quote.html",stock = stock, price = usd(stock["price"]), symbol = stock["symbol"])

        except:
            return apology("Something went wrong")

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        if not username:
            return apology("Username is required")
        if not password:
            return apology("Password is required")
        if not confirm_password:
            return apology("Confirmation is required")

        if password != confirm_password:
            return apology("Password must match!")

        try:
            hashed_password = generate_password_hash(password)
            user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
        except:
            return apology("Username already exists")

        session["user_id"] = user

        return redirect("/")
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Invalid number of shares")

        if not symbol:
            return apology("No symbol entered")
        if shares <= 0:
            return apology("Shares must be positive")

        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid symbol")

        user_id = session["user_id"]
        user_shares = db.execute("SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["total_shares"]

        if user_shares is None or user_shares < shares:
            return apology("Not enough shares")

        sale_value = shares * stock["price"]
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sale_value, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, opType, date) VALUES (?, ?, ?, ?, 'SELL', ?)", user_id, symbol, -shares, stock["price"], datetime.datetime.now())

        flash("Sold!")
        return redirect("/")
    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", symbols=symbols)

