
 > Changelog [V0-0-6]:

 - added required legal statements
 - removed option for manual entry when submitting VAT return
 - tested on Linux Mint (Ubuntu) 21.1 - Mate desktop

 > Install pre-requisites:

 - sudo pip3 install -r requirements.txt

 > Operation:

 - sudo ./main.py -i : install
 - ./main.py -g : generate new OTP secret
 - ./main.py -p : change user password
 - ./main.py : login
    > check : check vat no.
    > list : list all clients
    > create : create new client
    > select : select client
    > retrieve : retrieve returns/obligations
    > return : complete and send vat return
    > view : view return
    > save : save return to csv
    > liability : view unpaid bills
    > payments : view payments
    > exit : exit app

 > To generate TOTP from Python use:

 - pyotp.TOTP('BASE32SECRET').now()
