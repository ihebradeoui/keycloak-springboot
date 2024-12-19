package com.example.demo.controller;

import com.example.demo.config.acl.CustomAclService;
import com.example.demo.domain.entity.Course;
import com.example.demo.service.CourseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/demo")
public class DemoController {
    @Autowired
    CustomAclService customAclService;

    private final CourseService courseService;

    public DemoController(CourseService courseService) {
        this.courseService = courseService;
    }

    @GetMapping("/hello")
//s    @PreAuthorize("hasRole('ADMIN')")
    public String getDemo() {
        return "Hello World!";
    }

    @PostMapping("/courses")
    public Course createCourse(@AuthenticationPrincipal Jwt jwt, @RequestBody Course course) {
        Course savedCourse = courseService.save(course);
        customAclService.saveNewAcl(jwt, new ObjectIdentityImpl(savedCourse));
        return savedCourse;
    }

    @PostFilter("hasPermission(filterObject, 'READ') or hasPermission(filterObject, 'WRITE')")
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
