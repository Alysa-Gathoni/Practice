<?php
class fncs{
    public function setMsg($name, $values, $class){
        if(is_array($values)){
            $_SESSION[$name] = $values;
        }else{
            $_SESSION[$name] = '<span class="'.$class.'">'. $values .'</span>';
        }
    }
