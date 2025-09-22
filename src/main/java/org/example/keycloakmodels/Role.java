package org.example.keycloakmodels;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    private String id;
    private String name;
    private String description;
    private Boolean scopeParamRequired;
    private Boolean composite;
    private Boolean clientRole;
    private String containerId;
    //private Map<String, List<String>> attributes;

}
