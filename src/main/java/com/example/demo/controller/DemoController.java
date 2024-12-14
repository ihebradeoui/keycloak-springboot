package com.example.demo.controller;

import com.example.demo.domain.entity.Course;
import com.example.demo.service.CourseService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/demo")
public class DemoController {

    private final CourseService courseService;

    public DemoController(CourseService courseService) {
        this.courseService = courseService;
    }

    @GetMapping("/hello")
    @PreAuthorize("hasRole('ADMIN')")
    public String getDemo() {
        return "Hello World!";
    }

    @PostFilter("hasPermission(filterObject, 'READ')")
    @GetMapping("/courses")
    public List<Course> getCourses() {
        return courseService.findAll();
    }

    @PostAuthorize("hasPermission(returnObject, 'READ') and hasPermission(returnObject, 'WRITE')")
    @GetMapping("/courses/{id}")
    public Course getCourse(@PathVariable Long id) {
        return courseService.findById(id);
    }

}
