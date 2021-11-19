package com.sinda.produits.service;

import java.util.List;

import com.sinda.produits.entities.appartement;
import com.sinda.produits.entities.immeuble;

public interface AppartementService {
	appartement saveAppartement(appartement app);
	appartement updateAppartement(appartement app);
	void deleteAppartement(appartement app);
	 void deleteAppartementById(Long id);
	 appartement getAppartement(Long id);
	List<appartement> getAllAppartements();
	List<appartement> findByNomApp(String nom);
	List<appartement> findByNomAppContains(String nom);
	List<appartement> findByNomApp (String nom, String niveau);
	List<appartement> findByImmeuble (immeuble categorie);
	List<appartement> findByImmeubleIdIm(Long id);
	List<appartement> findByOrderByNomAppAsc();
	List<appartement> trierAppartementsNomsNiveaux();



}
