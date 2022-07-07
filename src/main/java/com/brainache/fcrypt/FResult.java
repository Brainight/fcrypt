/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.brainache.fcrypt;

/**
 *
 * @author Brainight
 */
public class FResult<T> {
    
    private final T target;
    private final boolean valid;
    private final String msg;
    
    public FResult(T target, boolean isValid, String msg){
        this.target = target;
        this.valid = isValid;
        this.msg = msg;
    }

    public T getTarget() {
        return target;
    }

    public boolean isValid() {
        return valid;
    }

    public String getMsg() {
        return msg;
    }
    
}
