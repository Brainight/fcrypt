/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.brainache.fcrypt.derivation;

import java.nio.charset.StandardCharsets;

/**
 *
 * @author Brainight
 */
public class HashId {
    
    protected final byte KDF_ID;
    protected final byte KDF_TYPE_ID;

    public HashId(byte KDF_ID, byte KDF_TYPE_ID) {
        this.KDF_ID = KDF_ID;
        this.KDF_TYPE_ID = KDF_TYPE_ID;
    }

    public byte getKDF_ID() {
        return KDF_ID;
    }

    public byte getKDF_TYPE_ID() {
        return KDF_TYPE_ID;
    }
    
    public byte[] getAsByteArray(){
        return new byte[]{KDF_ID, KDF_TYPE_ID};
    }
    
    public String getAsString(){
        return new String(getAsByteArray(), StandardCharsets.UTF_8);
    }
    
    
    
    
}
