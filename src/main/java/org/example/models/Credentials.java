package org.example.models;

import lombok.Data;

@Data
public class Credentials {
    private String type;
    private String value;
    private boolean temporary;
}
