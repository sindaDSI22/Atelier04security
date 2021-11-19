package com.sinda.produits.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sinda.produits.entities.appartement;
import com.sinda.produits.entities.immeuble;
import com.sinda.produits.repos.AppartementRepository;

@Service
public class AppartementServiceImpl implements AppartementService{
	@Autowired
    AppartementRepository appartementRepository;


	@Override
	public appartement saveAppartement(appartement app) {
		
		return appartementRepository.save(app);
	}

	@Override
	public appartement updateAppartement(appartement app) {
		return appartementRepository.save(app);
	}

	@Override
	public void deleteAppartement(appartement app) {
		appartementRepository.delete(app);
		
	}

	@Override
	public void deleteAppartementById(Long id) {
		appartementRepository.deleteById(id);
		
	}

	@Override
	public appartement getAppartement(Long id) {
		return appartementRepository.findById(id).get();

	}

	@Override
	public List<appartement> getAllAppartements() {
		return appartementRepository.findAll();
	}

	@Override
	public List<appartement> findByNomApp(String nom) {
		
		return appartementRepository.findByNomApp(nom);
	}

	@Override
	public List<appartement> findByNomAppContains(String nom) {
		
		return appartementRepository.findByNomAppContains(nom);
	}

	@Override
	public List<appartement> findByNomApp(String nom, String niveau) {
	
		return null;
	}

	@Override
	public List<appartement> findByImmeuble(immeuble im) {
		
		return appartementRepository.findByImmeuble(im);
	}

	@Override
	public List<appartement> findByImmeubleIdIm(Long id) {
		
		return appartementRepository.findByImmeubleIdIm(id);
	}

	@Override
	public List<appartement> findByOrderByNomAppAsc() {
		
		return appartementRepository.findByOrderByNomAppAsc();
	}

	@Override
	public List<appartement> trierAppartementsNomsNiveaux() {
		
		return appartementRepository.trierAppartementsNomsNiveaux();
	}

}
