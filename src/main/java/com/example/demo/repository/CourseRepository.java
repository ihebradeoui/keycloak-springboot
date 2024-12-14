package com.example.demo.repository;

import com.example.demo.domain.entity.Course;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CourseRepository extends CrudRepository<Course,Long> , JpaRepository<Course,Long> {
}
