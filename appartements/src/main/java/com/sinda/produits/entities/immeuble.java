package com.sinda.produits.entities;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;


import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class immeuble {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idIm;
	private String nomIm;
	private String adresse ;
	
	@JsonIgnore
	@OneToMany(mappedBy = "immeuble")
	private List<appartement> appartements;
	
	
}
