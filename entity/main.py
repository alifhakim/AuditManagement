from flask import Flask, render_template, url_for, flash, redirect
app = Flask(__name__)

@app.route("/")
@app.route("/allentities")
def allentities():
    return render_template('all_entities.html', title='All Entities')

@app.route("/communication")
def communication():
    return render_template('communication.html', title='Communication & Collaboration')

@app.route("/attachment")
def attachment():
    return render_template('attachment.html', title='Attachment')

@app.route("/otherproduct")
def otherproduct():
    return render_template('other_product.html', title='Other_Product')

@app.route("/othercust")
def othercust():
    return render_template('other_customer.html', title='Other_Customer')

if __name__ == '__main__':
    app.run(debug=True)