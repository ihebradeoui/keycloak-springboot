package com.example.demo.domain.entity;

import jakarta.persistence.*;
import lombok.Data;

@Table(name = "course")
@Entity
@Data

public class Course {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;
    String name;

}
