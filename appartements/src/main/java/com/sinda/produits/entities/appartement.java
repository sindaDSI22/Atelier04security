package com.sinda.produits.entities;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class appartement {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idApp;
	private String nomApp;
	private String niveau ;
	
	@ManyToOne
	private immeuble immeuble;
	
	
	public immeuble getImmeuble() {
		return immeuble;
	}
	public void setImmeuble(immeuble immeuble) {
		this.immeuble = immeuble;
	}
	public appartement() {
		super();
		// TODO Auto-generated constructor stub
	}
	public appartement(String nomApp, String niveau) {
		super();
		this.nomApp = nomApp;
		this.niveau = niveau;
	}
	
	public Long getIdApp() {
		return idApp;
	}
	public void setIdApp(Long idApp) {
		this.idApp = idApp;
	}
	public String getNomApp() {
		return nomApp;
	}
	public void setNomApp(String nomApp) {
		this.nomApp = nomApp;
	}
	public String getNiveau() {
		return niveau;
	}
	public void setNiveau(String niveau) {
		this.niveau = niveau;
	}
	@Override
	public String toString() {
		return "appartement [idApp=" + idApp + ", nomApp=" + nomApp + ", niveau=" + niveau + ", immeuble=" + immeuble
				+ "]";
	}


}
