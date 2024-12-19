package com.example.demo.domain.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.io.Serializable;

@Table(name = "course")
@Entity
@Data

public class Course implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    String name;

}
