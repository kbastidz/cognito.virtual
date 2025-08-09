package com.cognito.virtual;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@SpringBootApplication
@EnableAspectJAutoProxy
public class RecCognitoApplication {

	public static void main(String[] args) {
		SpringApplication.run(RecCognitoApplication.class, args);
	}

}
