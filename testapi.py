import flask
import re
from flask import *
import json;import os
import flask_wtf;from flask_wtf.csrf import CSRFProtect,CSRFError
import datetime
import uuid;from uuid import uuid1
import hashlib
import smtplib
import Queue
import urllib
from urllib import unquote
import urlparse;from urlparse import urlsplit
import cryptography
import flask_socketio;from flask_socketio import SocketIO
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import MySQLdb
import random_words;


otpcheck=set()


userheaders={
				'Cache-Control':"no-cache, no-store, must-revalidate",
				'Vary':"User-Agent, Accept-Encoding, Origin",
				'Pragma':"no-cache",
				'Connection':"close",
				'Strict-Transport-Security':"max-age=31564452; includeSubDomains",
				'Acces-Control-Allow-Origin':"http://192.168.56.101:7870/",
				'X-Content-Type':"nosniff",
				'Access-Control-Allow-Methods':"GET",
				'X-Frame-Options':"SAMEORIGIN"	
			}

usercreator=hashlib.new('sha256')

detailcollector={}
myhandlerset=Queue.Queue(maxsize=50000)
randstring=random_words.RandomWords()
mycookiedata=randstring.random_words(count=5000)
for p in mycookiedata:
	myhandlerset.put_nowait(p)

mykey=rsa.generate_private_key(public_exponent=65535,key_size=4096,backend=default_backend())
privatekey=mykey.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.BestAvailableEncryption("hacked"))
publichandler=mykey.public_key()
publickey=publichandler.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
 
authtoken=[]

urlcreate=[]
headers={'Content-Type':'application/json'}
handler=Flask(__name__)
handler.config['SECRET_KEY']=os.urandom(16)
handler.config['UPLOAD_FOLDER']="/upload/"


myserverhandler=SocketIO(handler)

mycsrftokenhanler=CSRFProtect(handler)

mysetsession=set()
keyhandler=Fernet.generate_key()
secretkey=Fernet(keyhandler)


usercreator.update(os.urandom(16))
myuserid=usercreator.hexdigest()
urlcreate.append(myuserid)
authorizationheader=str(str(secretkey.encrypt(usercreator.hexdigest())).replace("'","")).replace("==","")
otpcheck.add(authorizationheader)


@handler.route("/reset.html")
def makertest():
	m=make_response(render_template("reset.html"),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/profile.html")
def checks():
	m=make_response(render_template("/user/profile.html"),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

authenticationheader=uuid1()
usercreator.update(secretkey.encrypt(str(authenticationheader).encode(encoding="base64")))
finalauthheader=str(usercreator.hexdigest()).replace("'","")

@handler.route("/user/<userid>/logout.html")
def logout(userid):
	if request.method == "GET":
		session.pop('USER_SESSION_CLIENT')
		m= make_response(render_template("/login.html"))
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m


@handler.route("/user/<userid>/home.html",methods=['GET','POST'])
def mainuser(userid):
	if request.method == "GET":
		if 'USER_SESSION_CLIENT' in session:
			urlchecker=str(urlsplit(request.base_url)[2]).split("/")
			if str(urlchecker[2]).replace("'","") == str(userid).replace("'",""):
				pass
			else:
				m=make_response(json.dumps({'status':'Failed','message':'Unauthorized Access'}),401)
				sys.exit(1)
			clientmake_response=make_response(render_template("/user/home.html",CF_AUTH_ID=finalauthheader,authorizationuser=userid))
			return clientmake_response
		else:
			m=make_response(render_template("/login.html"),200)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
	else:
		m=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'},405))
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/otp.html",methods=['GET','POST','PUT'])
def testchecker():
	if request.method == "POST":
		try:
			userotpverify=request.form['OTP']
			if myuserid in urlcreate:
				clientuserid=urlcreate.index(myuserid)
				session['USER_SESSION_CLIENT']=finalauthheader

				return redirect(url_for('mainuser',userid=urlcreate[int(clientuserid)]))
			else:
				return "failed"

		except Exception as testing:
			print testing
			tmake_response=make_response(render_template('/error/400.html'),400)
			for i in userheaders:
				tmake_response.headers[i]=userheaders[i]
			return tmake_response
	elif request.method =="PUT":
		if request.form['Authentication_ID'] == str(finalauthheader):
			makemake_response=make_response(json.dumps({'status':'OK','Auth_ID':myuserid}),200)
			makemake_response.headers['Content-Type']="application/json"
			return makemake_response
		else:
			m=make_response(json.dumps({'status':'Failed','status':'Unauthorized'}),401)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
	else:	
		m=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m
		sys.exit(1)

testtoken=[]
@handler.route("/user/verification.html",methods=['GET','POST'])
def verficationtest():
	try:
		pass
	except:
		dataverify=str(verificationheader)


	if request.method == "POST":
		try:
			verificationheader=request.form['AuthorizationBear']
		except:
			forresp=make_response(render_template("/error/403.html"),403)
			for p in userheaders:
				forresp.headers[p]=userheaders[p]
			return forresp

		if verificationheader:
			testtoken.append(verificationheader)
			m=make_response(json.dumps({'status':'OK'}),200)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

		else:
			m=make_response(json.dumps({'status':'Failed','message':'Unauthorized'}),401)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
	elif request.method == "GET":
		try:
			authtoken.pop(0)
			m=make_response(render_template("/user/verification.html",requestauthorization=finalauthheader),200)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

		except:
			m=make_response(json.dumps({'status':'Failed','message':'Missing Authorization or Invalid Token'}),403);
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

	else:
		m=make_response(json.dumps({'status':'Failed','message':'Method Not allowed'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m
		sys.exit(1)


@handler.route("/contact.html")
def minnu():
	m=make_response(render_template("contact.html"),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/products2.html")
def product2():
	m=make_response(render_template("products2.html"),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

dbhandler=MySQLdb.connect(host="localhost",port=3306,user="root",passwd="",db="registration")
regcalculator="""^[\|/|&|;|,|'|"|<|'>|'/>|]|^[A-Za-z].*[/|<|>|*|+|].*"""
@handler.route("/register.html",methods=['GET','POST'])
def registration():
	if request.method == "POST":

		myexecute=dbhandler.cursor()		
		
		firstname=MySQLdb.escape_string(request.form['firstname'])
		lastname=MySQLdb.escape_string(request.form['lastname'])
		emailid=MySQLdb.escape_string(request.form['email'])
		phone=MySQLdb.escape_string(request.form['phone'])
		address=MySQLdb.escape_string(request.form['address'])
		country=MySQLdb.escape_string(request.form['country'])
		pincode=MySQLdb.escape_string(request.form['pin'])
		userpassword=MySQLdb.escape_string(request.form['testpassword'])
		if (len(firstname) or len(lastname) or len(emailid)) > 50:
			pass
			m=make_response(json.dumps({'status':'Failed','error':'true','message':'Exceed from character in firstname or lastname or emailid parameter'}),403)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

			sys.exit(1)
		elif len(phone) > 20:
			m=make_response(json.dumps({'status':'Failed','error':'true','message':'Exceed from characeter length in Phone paramter'}),403)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
		
		elif len(address) > 200:
			m=make_response(json.dumps({'status':'Failed','error':'true','message':'Exceed from characeter length in Address parameter'}),403)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
		else:
			pass

		if (re.match(regcalculator,firstname) or re.match(regcalculator,lastname) or re.match(regcalculator,emailid) or re.match(regcalculator,phone) or re.match(regcalculator,address) or re.match(regcalculator,country) or re.match(regcalculator,pincode)) == True:
			m=make_response(json.dumps({'status':'Failed','error':'true','message':'Special Characters are not allowed'}),403)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)

		if not (emailid.endswith(".com") or emailid.endswith(".in") or emailid.endswith(".org") or emailid.endswith(".gov")):
			m=make_response(json.dumps({"status":"failed","error":"true","message":"Invalid Email Address"}),429)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)

		uuid="""os.mkdir("/home/jack/pythonweb/templates/user/api/%s" % str(myuserid).replace("'",""))"""

		try:

			myverification=myexecute.execute("SELECT * FROM newregistration WHERE Emailid='%s';" % (emailid))
			anothercheck=myexecute.fetchall()

			if myverification:
				m=make_response(json.dumps({"status":"Failed","error":"true","message":"The Email is already associated with another account"}),400)
				m.headers['Content-Type']="application/json"
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return m
				sys.exit(1)
						
			else:
				try:
					eval(uuid)
				except:
					pass
				myexecute.execute("INSERT INTO newregistration(Firstname,Lastname,Emailid,Phone,Address,Country,Pincode,UID) VALUES('%s','%s','%s','%s','%s','%s','%s','%s');" % (str(firstname),str(lastname),str(emailid),str(phone),str(address),str(country),str(pincode),str(myuserid).replace("'","")))
				myexecute.execute("INSERT INTO record(Username,Password,ClientUID)VALUES('%s','%s','%s');" % (str(firstname),str(userpassword),str(myuserid)));
				dbhandler.commit()
				m=make_response(json.dumps({"status":"success","message":"OK","AuthorizationBear":"%s" % (authorizationheader)}),201)
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return redirect(url_for('verficationtest'))
		
		except MySQLdb.Error as testvalue:
				print testvalue
				eval(uuid)
				myexecute.execute("CREATE TABLE newregistration(Firstname VARCHAR(20),Lastname VARCHAR(20),Emailid VARCHAR(50),Phone VARCHAR(20), Address VARCHAR(20),Country VARCHAR(20),Pincode VARCHAR(20),Password VARCHAR(20),UID VARCHAR(100));")
				myexecute.execute("INSERT INTO newregistration(Firstname,Lastname,Emailid,Phone,Address,Country,Pincode,Password,UID) VALUES('%s','%s','%s','%s','%s','%s','%s','%s','%s');" % (str(firstname),str(lastname),str(emailid),str(phone),str(address),str(country),str(pincode),str(userpassword),str(myuserid).replace("'","")))
				dbhandler.commit()
				m=make_response(json.dumps({"status":"success","message":"OK","AuthorizationBear":"%s" % (authorizationheader)}),201)
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return m
		
		except MySQLdb.ProgrammingError as errormysql:
			print errormysql
			m=make_response(json.dumps({"status":"Failed","Message":"Something is Wrong Please Try again"}),500)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

	elif request.method == "GET":
		authvalue=usercreator.update(os.urandom(16))
		finaltoken=usercreator.hexdigest()
		authtoken.append(finaltoken)
		m=make_response(render_template("/register.html",AuthenticationToken=finaltoken),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

	else:
		am=make_response(json.dumps({'status':'Failed',"message":'Method Not Allowed'}),405)
		am.headers['Content-Type']="application/json"
		for i in userheaders:
			am.headers[i]=userheaders[i]
		return am

	m=make_response(render_template("/register.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m


goliset=[]
@handler.route("/user/<userid>/EditDetail",methods=['POST','PUT','GET'])
def detailhandler(userid):
	if request.method == 'PUT':
		try:
			userfirstname=MySQLdb.escape_string(request.form['Firstname'])
			userlastname=MySQLdb.escape_string(request.form['Lastname'])
			usermobile=MySQLdb.escape_string(request.form['Mobile'])
			useremail=MySQLdb.escape_string(request.form['Email'])
			useridchecker=MySQLdb.escape_string(request.form['Userid'])
			goliset.append(useremail)
			userpass=str(MySQLdb.escape_string(request.form['Password'])).decode(encoding="base64")
			updatedetail=dbhandler.cursor()
			updatedetail.execute("UPDATE newregistration SET Emailid='%s',Lastname='%s',Phone='%s',Firstname='%s',Password='%s' WHERE UID='%s';" % (useremail,userlastname,usermobile,userfirstname,userpass,str(useridchecker)))
			dbhandler.commit()
			sendmake_response=make_response(json.dumps({'status':'success','message':'Successfully Updated'}))
			sendmake_response.headers['Content-Type']="application/json"
			return sendmake_response
		except:
			errormake_response=make_response(json.dumps({'status':'Failed','message':'Unauthorized'}),401)
			errormake_response.headers['Content-Type']="application/json"
			return errormake_response

	elif request.method == "POST":
		try:
			userimage=request.files['filebtn']
			userimage.save(userimage.filename)
			tester=make_response(json.dumps({'status':'success','message':'Successfully Updated'}))
			tester.headers['Content-Type']='application/json'
			for i in userheaders:
				tester.headers[i]=userheaders[i]
			return tester
		except:
			errhandler=make_response(json.dumps({'status':'Failed','message':'Profile Not Updated'}))
			errhandler.headers['Content-Type']="application/json"
			for i in userheaders:
				errhandler.headers[i]=userheaders[i]
			return errhandler
	else:
		testmake_response=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'}),405)
		for i in userheaders:
			testmake_response.headers[i]=userheaders[i]
		return testmake_response

@handler.route("/user/<userid>/RealTime",methods=['POST'])
def currentuservalue(userid):
	if request.method == "POST":
		try:
			testid=request.form['CurrentUserID']
			request.form['EmailID']
		except:
			err=make_response(json.dumps({'status':'Failed','message':'Invalid Parameter'}),400)
			err.headers['Content-Type']="application/json"
			for i in userheaders:
				err.headers[i]=userheaders[i]
			return err
			sys.exit(1)
		currentupdate=dbhandler.cursor()
		currentupdate.execute("SELECT * FROM newregistration WHERE UID='%s';" % (testid))
		finalhandler=currentupdate.fetchall()[0]
		currentmake_response=make_response(json.dumps({'status':'OK','firstname':finalhandler[0],'lastname':finalhandler[1],'email':finalhandler[2],'mobile':finalhandler[3],'Password':str(str(finalhandler[7]).encode(encoding="base64")).replace("'",""),'uid':finalhandler[8]}),200)
		currentmake_response.headers['Content-Type']="application/json"
		for i in userheaders:
			currentmake_response.headers[i]=userheaders[i]
		return currentmake_response
	else:
		abcd=make_response(json.dumps({'status':'Failed','messgae':'Method Not Allowerd'}),405)
		abcd.headers['Content-Type']="application/json"
		for i in userheaders:
			abcd.headers[i]=userheaders[i]
		return abcd

@handler.route("/products.html")
def myproducts():
	m=make_response(render_template("products.html"),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/<userid>/OnlinePayment.html")
def processor(userid):
	if 'USER_SESSION_CLIENT' in session:
		p=make_response(render_template("/user/OnlinePayment.html",userid=userid),200)
		for i in userheaders:
			p.headers[i]=userheaders[i]
		return p
	else:
		m=make_response(render_template("/login.html"),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/<userid>/products.html")
def myauthuser(userid):
	if request.method =="GET":
		m=make_response(render_template("/user/products.html",clientauthid=userid),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

	else:
		m=make_response(json.dumps({'status':'failed','message':'Method Not Allowerd'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/<userid>/contact.html")
def contactauth(userid):
	m=make_response(render_template("/user/contact.html",userid=userid),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m


@handler.route("/user/<userid>/about.html")
def aboutauth(userid):
	if 'USER_SESSION_CLIENT' in session:
		m=make_response(render_template("/user/about.html",userid=userid),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m
	else:
		m.make_response(render_template("/login.html"),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/<userid>/PaymentOTP.html",methods=['GET','POST'])
def completeotp(userid):
	if 'USER_SESSION_CLIENT' in session:
		m=make_response(render_template("/user/PaymentOTP.html"),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m
	else:
		m=make_response(render_template("/login.html"),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m


@handler.route("/user/<userid>/DiscardItem",methods=['DELETE'])
def deleter(userid):
	if 'USER_SESSION_CLIENT' in session:
		if request.method == "DELETE":
			try:
				deleterequest=request.form['Target']
				with open("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid),'a+') as jsonreader:
					deletejson=json.load(jsonreader)
					for i in deletejson['Products']:
						if str(i['name']) == str(deleterequest):
							deletejson['Products'].remove(i)

				with open("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid),"a+" ) as updater:
					updater.truncate(0)
					json.dump(deletejson,updater,indent=4)
				testgoli=make_response(json.dumps({'status':'success','message':'Deleted Successfully'}),200);
				testgoli.headers['Content-Type']="application/json"
				for i in userheaders:
					testgoli.headers[i]=userheaders[i]
				return testgoli
			except Exception as te:
				retmake_response=make_response(json.dumps({'status':'Failed','message':'Invalid Parameter'}),400)
				retmake_response.headers['Content-Type']="application/json"
				for i in userheaders:
					retmake_response.headers[i]=userheaders[i]
				return retmake_response

		else:
			delmake_response=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'}),405)
			delmake_response.headers['Content-Type']="application/json"
			for i in userheaders:
				delrespnose[i]=userheaders[i]
			return delrespnose
	else:
		m=make_response(render_template('/login.html'),200)
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m


@handler.route("/user/<userid>/Shoppingcart.html",methods=['GET'])
def cartchecker(userid):
	if request.method == "GET":
		if 'USER_SESSION_CLIENT' in session:
			if not  os.path.exists("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid)):
				emmake_response=make_response(render_template("/user/EmptyCart.html"),200)
				for i in userheaders:
					emmake_response.headers[i]=userheaders[i]
				return emmake_response
			elif os.path.getsize("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid)) == 0 or len(json.load(open("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid),'rb'))['Products']) == 0:
				empmake_response=make_response(render_template("/user/EmptyCart.html",authorizedid=myuserid))
				for i in userheaders:
					empmake_response.headers[i]=userheaders[i]
				return empmake_response;
			else:
				m=make_response(render_template("/user/Shoppingcart.html",authorizedid=myuserid,clienttoken=finalauthheader))
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return m

		else:
			eresp=make_response(render_template("/login.html"),200)
			for i in userheaders:
				eresp.headers[i]=userheaders[i]
			return eresp
	else:
		t=make_response(json.dumps({'status':'Failed','message':'Method Not Allowerd'}),405)
		t.headers['Content-Type']="application/json"
		for pl in userheaders:
			t.headers[pl]=userheaders[pl]
		return t

@handler.route("/user/<userid>/cart.json",methods=['GET'])
def jsonrender(userid):
	try:
		if 'USER_SESSION_CLIENT' in session:
			jsonmake_responsehandler=make_response(render_template("/user/api/%s/cart.json" % (userid)))
			jsonmake_responsehandler.headers['Content-Type']="application/json";
			return jsonmake_responsehandler
		else:
			m=make_response(render_template("/login.html"),200)
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

	except Exception as ef:
		print ef
		jsonmake_response=make_response(render_template("/error/404.html"))
		return jsonmake_response

@handler.route("/user/<userid>/products2.html")
def product2auth(userid):
	m=make_response(render_template("/user/products2.html",userid=userid),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/<userid>/products3.html")
def product3auth(userid):
	m=make_response(render_template("/user/products3.html",userid=userid),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/products3.html")
def myresult():
	m=make_response(render_template("products3.html",userid=userid),200)
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/product.json")
def myjson():
	m=make_response(render_template("product.json"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/about.html")
def about():
	m=make_response(render_template("about.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/<userid>/complete.html",methods=['GET'])
def finalcomplete(userid):
	if 'USER_SESSION_CLIENT' in session:
		if request.method == "GET":			
			t=make_response(render_template("/user/complete.html"),200)
			for i in userheaders:
				t.headers[i]=userheaders[i]
			return t
		else:
			t=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'}),405)
			t.headers['Content-Type']="application/json"
			for i in userheaders:
				t.headers[i]=userheaders[i]
			return t
	else:
		m=make_response(render_template("/login.html"))
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/<userid>/buy.html", methods=['GET','PUT'])
def buyproduct(userid):
	if request.method == "GET":
		if 'USER_SESSION_CLIENT' in session:
			if str(userid) in urlcreate:
				usercreator.update(str(uuid.uuid1()).encode(encoding="base64"))
				maker=usercreator.hexdigest()
				transactionid=str(str(str(publichandler.encrypt(maker,padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA512(),label=None))).encode(encoding="base64")).replace("'","")).replace("=\n","")

				m=make_response(render_template("/user/buy/buy.html",Authorizeduserid=userid,authheader=finalauthheader,transaction=transactionid))
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return m
		else:
			loginredirect=make_response(render_template("/login.html"),200)
			for i in userheaders:
				loginredirect.headers[i]=userheaders[i]
			return loginredirect

	elif request.method == "PUT":
		if request.form['Quantity'] == "":
			m=make_response(json.dumps({"status":"Failed","message":"Invalid product Quantity"}),422)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
		else:
			try:
				carthandler=request.form['ClientAuthID']
				itemuri=request.form['producturi']
				statusvalue=request.form['AddToCart']
				quantityofproduct=int(request.form['Quantity'])
				productname=urllib.unquote(request.form['Productname'])
				productprice=int(str(request.form['Productprice']).replace("Rs.",""))

			except Exception as ex:
				print ex
				m=make_response(json.dumps({'status':'Failed',"message":'Exception Occured in Your Request'}),400)
				m.headers['Content-Type']="application/json"
				for i in userheaders:
					m.headers[i]=userheaders[i]
				return m
				sys.exit(1)
			myurl=request.base_url
			location=urlsplit(myurl)[2]
			finallocation=location.split("/")[2]

			with open('/home/jack/pythonweb/templates/user/api/%s/cart.json' % (str(finallocation)) ,"a+") as fp:
				jsonobject={
								"Products":[
												{
													'name':productname,
													'url':itemuri,
													'quantity':quantityofproduct,
													'Price':productprice*quantityofproduct

												}
											]
										
							}
		
				if os.path.getsize("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (userid)) == 0:
					fp.write(json.dumps(jsonobject,indent=4));
				elif len(json.load(fp)['Products']) == 0:
					fp.truncate(0)
					json.dump(jsonobject,fp,indent=4)

				else:
					def jsoncatcher(jsondata):
						with open("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (str(finallocation)),"w") as mp:
							json.dump(jsondata,mp,indent=4)

					with open("/home/jack/pythonweb/templates/user/api/%s/cart.json" % (str(finallocation)),"a+") as reader:
						jsondata=json.load(reader)
						verifydata=jsondata['Products']
						for goli in verifydata:
							if str(productname) in goli.values():
								goli['quantity']=int(goli['quantity'])+int(quantityofproduct)
								testprice=int(productprice)*int(quantityofproduct)
								goli['Price']=int(goli['Price'])+testprice
								json.dump(int(goli['quantity']),reader)
								break
							else:
								break
				

						for cs in verifydata:
							if str(productname) == str(cs['name']):
								goli['quantity']=int(goli['quantity'])+int(quantityofproduct)
								testprice=int(productprice)*int(quantityofproduct)
								goli['Price']=int(goli['Price'])+testprice
								json.dump(int(goli['quantity']),reader)
								break
				
							else:
								producttest={'name':productname,'url':itemuri,'quantity':quantityofproduct,'Price':int(productprice)*int(quantityofproduct)}
								temp=jsondata['Products']
								temp.append(producttest)
								break
							
					jsoncatcher(jsondata)
				

			m=make_response(json.dumps({"status":"OK","message":"Successfully Added"}),201)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m

	else:
		m=make_response(json.dumps({"status":'Failed',"message":'Method Not Allowed'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m

@handler.route("/user/HelpSupport/<userid>/shopcard.html")
def purchasing(userid):
	m=make_response(render_template("/user/HelpSupport/shopcard.html",userid=userid))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/HelpSupport/<userid>/techsupport.html")
def TechnicalProblem(userid):
	m=make_response(render_template("/user/HelpSupport/techsupport.html",userid=userid))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/HelpSupport/<userid>/acblock.html")
def acerror(userid):
	m=make_response(render_template("/user/HelpSupport/acblock.html",userid=userid))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/user/HelpSupport/<userid>/accountdeactivation.html")
def deactivation(userid):
	m=make_response(render_template("/user/HelpSupport/accountdeactivation.html",userid=userid))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m


@handler.route("/user/HelpSupport/<userid>/privacy.html")
def privacyinfo(userid):
	m=make_response(render_template("/user/HelpSupport/privacy.html",userid=userid))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m


@handler.route("/products4.html")
def finaltemp():
	m=make_response(render_template("products4.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/error/404.html")
def errohadler404():
	m=make_response(render_template("/error/404.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/error/400.html")
def errorhandler400():
	m=make_response(render_template("/error/400.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@handler.route("/error/403.html")
def errorhandler403():
	m=make_response(render_template("/error/403.html"))
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@myserverhandler.on('connect')
def broadcasting(message):
	emit("How May I Can help you")

@myserverhandler.on('message')
def usermsghandler(message):
	emit(message)
	print message


@handler.errorhandler(CSRFError)
def csrferror(CSRFError):
	m=make_response(json.dumps({'error':'true','message':'Invalid Token'}),400)
	m.headers['Content-Type']="application/json"
	for i in userheaders:
		m.headers[i]=userheaders[i]
	return m

@myserverhandler.on('error')
def errorhandler(e):
	print e


@handler.route("/user/<userid>/settings.html",methods=['GET','POST','PUT'])
def accounthandler(userid):
	if request.method=="GET":
		cachemake_response=make_response(render_template("/user/settings.html",userid=userid))
		for i in userheaders:
			cachemake_response.headers[i]=userheaders[i]
		return cachemake_response

	elif request.method == "POST":
		pass
	else:
		errorresp=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'},405))
		errorresp.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return errorresp

@handler.route("/",methods=['GET'])
def indexhandler():
	if request.method == "GET":
		indexmake_response=make_response(render_template("/index.html"),200)
		for myheaders in userheaders:
			indexmake_response.headers[myheaders]=userheaders[myheaders]

		indexmake_response.set_cookie("CF_USER_ID","%s" % (secretkey.encrypt(str(uuid.uuid1()).encode(encoding="base64"))),max_age=90*9000,httponly=True)

		return indexmake_response
	else:
		m=make_response(json.dumps({'status':'Failed','message':'Method Not Allowed'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m


cookieexpiration=datetime.datetime(2022,1,1)
# authentication hash calculator
cookiestore=[]
myhashhandler=hashlib.new('SHA512')


@handler.route("/login.html",methods=['GET','POST'])
def myredirecthandler():
	
	if request.method == "POST":
		authuser=MySQLdb.escape_string(request.form['user'])
		authpassw=MySQLdb.escape_string(request.form['passw'])
		length=request.form['height']
		breath=request.form['width']
		make_responser=request.form['hostname']
		versionengine=request.form['engineversion']
		system=request.form['platform']
		supportlanguage=request.form['language']
		baseuri=request.form['url']
		useragent=request.form['UserAgent']
		protocolschema=request.form['protocol']
		parameterurl=request.form['pathnames']
		cookietester=request.form['cookiecheck']
		browserfullname=request.form['browsername']
		enginename=request.form['engine']

		if request.form['user'] == "" or request.form['passw'] == "":
			m=make_response(json.dumps({"status":"Failed","message":"Invalid parameters"}),400)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
		elif re.match(regcalculator,request.form['user']):
			m=make_response(json.dumps({'status':'Faied',"message":'Special Characters not Allowerd'}),403)
			m.headers['Content-Type']="application/json"
			for i in userheaders:
				m.headers[i]=userheaders[i]
			return m
			sys.exit(1)
		else:
			mysqlconnection=MySQLdb.connect(host="localhost",port=3306,user="root",passwd="")
			mycursor=mysqlconnection.cursor()
			mysqlconnection.select_db("registration")
			myfetcher=mycursor.execute("SELECT * FROM record WHERE Username='%s';" % (str(authuser)))
			mydata=mycursor.fetchall()

			if mycursor.execute("SELECT * FROM record;") == int(0):
				mysqlconnection.commit()
				return redirect(url_for('mainuser',redirectid=myuserid))
			else:
				mydatauser=mydata[0][0]
				mydatapassword=mydata[0][1]
				clientid=mydata[0][2]
				if mydatauser == str(authuser) and mydatapassword == str(authpassw):
					mysession=str(secretkey.encrypt(str(authuser)+str(authpassw))).encode(encoding="base64")
					mycurrentsession=session['CF_UID']=mysession
					mysetsession.add(mysession)
					#m=make_response(json.dumps({"status":'OK',"message":"success"}),200)
					return redirect(url_for('mainuser',redirectid=clientid))
				else:
					m=make_response(json.dumps({'status':'Failed','message':'Invalid Usernamd or Password'}),401)
					m.headers['Content-Type']="application/json"
					for i in userheaders:
						m.headers[i]=userheaders[i]
					return m
					sys.exit(1)

	else:
		m=make_response(json.dumps({'status':'failed','reason':'method not allowerd'}),405)
		m.headers['Content-Type']="application/json"
		for i in userheaders:
			m.headers[i]=userheaders[i]
		return m



if __name__ == "__main__":
	#handler.run(host="192.168.56.101",port=7870,debug=True)
	myserverhandler.run(handler,host="192.168.56.101",port=7870,debug=True)