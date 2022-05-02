/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.oracle.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class Wallet extends Applet {

    /* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Wallet_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte RESET_PIN_COUNTER = (byte) 0x2C;
    
    final static byte MONEY = 0x01;
    final static byte LITERS = 0x02;

    // maximum balance
    final static short MAX_BALANCE = 4000;
    // maximum liters balance
    final static short MAX_LITERS = 500;
    // maximum transaction amount
    final static short MAX_TRANSACTION_AMOUNT = 250;
    
    // maximum transaction amount for the debit action
    final static byte MAX_DEBIT_TRANSACTION_AMOUNT = 50;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal that the liters balance exceeds the maximum
    final static short SW_EXCEED_MAXIMUM_LITERS = 0x6A8A;
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    

    final static byte[] PUK = {(byte) 0x09, (byte) 0x09, (byte) 0x09, (byte) 0x09, (byte) 0x09, (byte) 0x09, (byte) 0x09, (byte) 0x09};
    /* instance variables declaration */
    OwnerPIN pin;
    short balance;
    short liters;
    

    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case RESET_PIN_COUNTER:
            	reset_pin_try_counter(apdu);
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method

    private void credit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        
        // get instruction parameters
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        
        // check if the parameters are valid
        if (p1 != MONEY && p1 != LITERS) {
        	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if(p2 != MONEY && p2 != LITERS && p2 != 0) {
        	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        // Because the maximum transaction amount is 250, which fits in a byte, LC will be a maximum of 2
        // because we can credit both money and liters, otherwise LC will be 1
        // if 2 bytes are read but p2 was not given, an error is thrown
        if (numBytes != byteRead || numBytes > 2 || (numBytes == 2 && p2 == 0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount
        
        short amount1 = 0;
        short amount2 = 0;
        
        amount1 = (short) (buffer[ISO7816.OFFSET_CDATA] & 0xFF);
        
        // if there is P2, we get that amount
        if(p2 == MONEY || p2 == LITERS)
        {
        	if (numBytes == 2) {
        		amount2 = (short) (buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF);
            }
        	else
        	{
        		// the parameters for the instructions has been provided
        		// but the value has not been
        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	}
        }

        // check the credit amount
        if ((amount1 > MAX_TRANSACTION_AMOUNT) || (amount1 < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        
        if(p2 == MONEY || p2 == LITERS)
        {
        	if ((amount2 > MAX_TRANSACTION_AMOUNT) || (amount2 < 0)) {
                ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
            }
        }

        // check the new balance - RON
        if(p1 == MONEY)
        {
        	if(balance + amount1 > MAX_BALANCE) {
            	ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
            }
        	
        	balance += amount1;
        }
        else if(p2 == MONEY)
        {
        	if(balance + amount2 > MAX_BALANCE) {
            	ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
            }
        	balance += amount2;
        }
        
        // check the new balance - LITERS
        if(p1 == LITERS)
        {
        	if(liters + amount1 > MAX_LITERS) {
            	ISOException.throwIt(SW_EXCEED_MAXIMUM_LITERS);
            }
        	liters += amount1;
        }
        else if(p2 == LITERS)
        {
        	if(liters + amount2 > MAX_LITERS) {
            	ISOException.throwIt(SW_EXCEED_MAXIMUM_LITERS);
            }
        	liters += amount2;
        }

    } // end of deposit method

    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        
        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        
        // Because the maximum transaction amount is 50, which fits in a byte, LC will be a maximum of 1
        if (numBytes != byteRead || numBytes > 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get debit amount
        short debitAmount = 0;
        if (numBytes == 1) {
        	debitAmount = (short) (buffer[ISO7816.OFFSET_CDATA] & 0xFF);
        }
        
        // check debit amount
        if ((debitAmount > MAX_DEBIT_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        // if the transaction can be realised with only liters, it will be done that way
        if(liters >= debitAmount)
        {
        	liters -= debitAmount;
        }
        else 
        {
        	// the debit amount exceeds the account liters balance
        	// so the client has to pay the rest with money 
        	
        	// we check that the client has enough money balance to realise the transaction
        	// because 1 liter = 8 RON => we multiply the remaining amount with 8 to obtain the RON equivalent of the remaining debit amount
        	// if the RON equivalent exceeds the current balance, an error is thrown
        	if ((debitAmount - liters) * 8 > balance)
        	{
        		ISOException.throwIt(SW_NEGATIVE_BALANCE);
        	}
        	// we subtract the remaining debit amount in RON from the balance
        	balance -= (debitAmount - liters) * 8;
        	// After the transaction, liters will be 0
        	// It will be replaced by the integer part of RON equivalent of the debit value
        	// divided by 100
        	liters = (short) (((debitAmount - liters) * 8) / 100);
        	 
        }

    } // end of debit method

    private void getBalance(APDU apdu) {
    	
    	// In the exercise, every operation can be realised only when the pin is the verified
    	if(!pin.isValidated()) {
    		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    	}

        byte[] buffer = apdu.getBuffer();
        
        // get the instruction parameters
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        
        // check if the parameters are valid
        if (p1 != MONEY && p1 != LITERS) {
        	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        if(p2 != MONEY && p2 != LITERS && p2 != 0) {
        	ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field
        short le = apdu.setOutgoing();

        // The output will have the formats
        // BALANCE_TYPE BYTE1 BYTE2
        // or
        // BALANCE_TYPE1 BYTE1 BYTE2 BALANCE_TYPE2 BYTE1 BYTE2
        // if LE is less than 3 or bigger than 6, an error is thrown
        if (le < 3 || le > 6) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // informs the CAD the actual number of bytes
        // returned
        apdu.setOutgoingLength((byte) le);

        // move the balance data into the APDU buffer
        // starting at the offset 0
        if (p1 == MONEY) {
        	buffer[0] = MONEY;
        	buffer[1] = (byte) (balance >> 8);
        	buffer[2] = (byte) (balance & 0xFF);
        }
        else {
        	buffer[0] = LITERS;
        	buffer[1] = (byte) (liters >> 8);
        	buffer[2] = (byte) (liters & 0xFF);
        }
        
        if (p2 == MONEY) {
        	buffer[3] = MONEY;
        	buffer[4] = (byte) (balance >> 8);
        	buffer[5] = (byte) (balance & 0xFF);
        }
        else if (p2 == LITERS){
        	buffer[3] = LITERS;
        	buffer[4] = (byte) (liters >> 8);
        	buffer[5] = (byte) (liters & 0xFF);
        }
        
        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) le);
        
        
    } // end of getBalance method

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.getTriesRemaining() == 0) {
        	ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        	return;
        }
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

    } // end of validate method
    
    private void reset_pin_try_counter(APDU apdu) {
		if (pin.getTriesRemaining() != 0) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return;
		}
		
		byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        
        if (byteRead != PUK.length) {
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	return;
        }
        
        for (byte i=0; i<PUK.length; i++)
        {
        	if (buffer[ISO7816.OFFSET_CDATA + i] != PUK[i]) {
        		ISOException.throwIt(SW_VERIFICATION_FAILED);
        		return;
        	}
        }
        
        pin.resetAndUnblock();
        
	}
} // end of class Wallet

