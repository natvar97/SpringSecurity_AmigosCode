package com.example.springboot_amigoscode_demo_1.student;


import ch.qos.logback.core.rolling.helper.IntegerTokenConverter;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "Uru"),
            new Student(2, "Natu"),
            new Student(3, "Hardy"),
            new Student(4, "Bholu"),
            new Student(5, "Dolyo")
    );

    // hasRole('ROLE_') , hasAnyRole('ROLE_') , hasAuthority('permission') , hasAnyAuthority('permission')

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMIN_TRAINEE')")
    public List<Student> getStudents() {
        System.out.println("getStudents");
        return students;
    }

    @GetMapping("{studentId}")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMIN_TRAINEE')")
    public Student getStudentById(@PathVariable("studentId") Integer studentId) {
        System.out.println("get Student by their id");
        return students.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Student with id " + studentId + " not found"
                ));
    }


    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerStudent(@RequestBody Student student) {
        System.out.println("register student");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("delete student");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("update student");
        System.out.printf("%s %s%n", studentId, student);
    }


}
