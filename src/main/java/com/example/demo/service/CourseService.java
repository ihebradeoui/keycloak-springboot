package com.example.demo.service;

import com.example.demo.domain.entity.Course;
import com.example.demo.repository.CourseRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CourseService {
    private CourseRepository courseRepository;

    public CourseService(CourseRepository courseRepository) {
        this.courseRepository = courseRepository;
    }
    public Course save(Course course){
        return courseRepository.save(course);
    }
    public Course findById(Long id){
        return courseRepository.findById(id).orElse(null);
    }
    public List<Course> findAll(){
        return courseRepository.findAll();
    }
}
