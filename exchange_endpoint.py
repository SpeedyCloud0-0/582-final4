from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

def check_sig(payload,sig):
	signature = sig
    message = json.dumps(payload)
    pk = payload.get("sender_pk")
    platform = payload.get("platform")
    if platform == 'Ethereum':
        # Check if signature is valid
        encoded_msg = eth_account.messages.encode_defunct(text=message)
        result = (eth_account.Account.recover_message(encoded_msg, signature=signature) == pk)
    else:
        # Check if signature is valid
        result = algosdk.util.verify_bytes(message.encode('utf-8'), signature, pk)
    return result

def fill_order(order,txes=[]):
	# if isinstance(order, dict):
 #        order_obj = Order(sender_pk=order['sender_pk'], receiver_pk=order['receiver_pk'],
 #                          buy_currency=order['buy_currency'], sell_currency=order['sell_currency'],
 #                          buy_amount=order['buy_amount'], sell_amount=order['sell_amount'])
 #    else:
 #        order_obj = order
 #        session.add(order_obj)
 #    	session.commit()

	matched = False
    for existing_oder in txes:
        if existing_oder.buy_currency == order_obj.sell_currency and \
                existing_oder.sell_currency == order_obj.buy_currency:
            if existing_oder.sell_amount / existing_oder.buy_amount >= order_obj.buy_amount / order_obj.sell_amount:
                # If a match is found
                matched = True
                existing_oder.filled = datetime.now()
                order_obj.filled = datetime.now()
                existing_oder.counterparty_id = order_obj.id
                order_obj.counterparty_id = existing_oder.id
                session.commit()
                break

    if matched:
        # If one of the orders is not completely filled
        if existing_oder.sell_amount < order_obj.buy_amount:
            new_order_obj = Order(sender_pk=order_obj.sender_pk, receiver_pk=order_obj.receiver_pk,
                                  buy_currency=order_obj.buy_currency, sell_currency=order_obj.sell_currency,
                                  buy_amount=order_obj.buy_amount - existing_oder.sell_amount,
                                  sell_amount=order_obj.sell_amount - existing_oder.buy_amount,
                                  creator_id=order_obj.id)

        elif order_obj.sell_amount < existing_oder.buy_amount:
            new_order_obj = Order(sender_pk=existing_oder.sender_pk, receiver_pk=existing_oder.receiver_pk,
                                  buy_currency=existing_oder.buy_currency,
                                  sell_currency=existing_oder.sell_currency,
                                  buy_amount=existing_oder.buy_amount - order_obj.sell_amount,
                                  sell_amount=existing_oder.sell_amount - order_obj.buy_amount,
                                  creator_id=existing_oder.id)
        else:
            return
        g.session.add(new_order_obj)
        g.session.commit()
        fill_order(new_order_obj)

    pass
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form

    pass

""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        payload = content.get("payload")
        sig = content.get("sig")
        result = check_sig(payload,sig)

        # TODO: Add the order to the database
        if result:
            order = content['payload']
            order_obj = Order(sender_pk=order['sender_pk'], receiver_pk=order['receiver_pk'],
                              buy_currency=order['buy_currency'], sell_currency=order['sell_currency'],
                              buy_amount=order['buy_amount'], sell_amount=order['sell_amount'],
                              signature=content['sig'])
            g.session.add(order_obj)
            g.session.commit()  
            # return jsonify(True)
        else:
            log_message(payload)
            return jsonify(False)

        # TODO: Fill the order
		orders = [order for order in g.session.query(Order).filter(Order.filled == None).all()]
		fill_order(order_obj, orders)
        
        return jsonify(True)
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
        

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    orders = [order for order in g.session.query(Order).all()]
    data = []
    for existing_oder in orders:
        json_order = {'sender_pk': existing_oder.sender_pk, 'receiver_pk': existing_oder.receiver_pk,
                      'buy_currency': existing_oder.buy_currency, 'sell_currency': existing_oder.sell_currency,
                      'buy_amount': existing_oder.buy_amount, 'sell_amount': existing_oder.sell_amount,
                      'signature': existing_oder.signature}

        data.append(json_order)
    result = {"data": data}
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')