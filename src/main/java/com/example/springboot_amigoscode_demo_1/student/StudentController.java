package com.example.springboot_amigoscode_demo_1.student;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "Uru"),
            new Student(2, "Natu"),
            new Student(3, "Hardy"),
            new Student(4, "Bholu"),
            new Student(5, "Dolyo")
    );

    @GetMapping("{studentId}")
    public Student getStudentById(@PathVariable("studentId") Integer studentId) {
        return students.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Student with id:" + studentId + " not found")
                );
    }

    @GetMapping("")
    public List<Student> getAllStudents() {
        return students;
    }

}
