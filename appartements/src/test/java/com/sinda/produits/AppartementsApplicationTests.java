package com.sinda.produits;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.sinda.produits.entities.appartement;
import com.sinda.produits.entities.immeuble;
import com.sinda.produits.repos.AppartementRepository;

@SpringBootTest
class AppartementsApplicationTests {
	
	@Autowired
	private AppartementRepository appartementRepository;
	
	@Test
	public void testCreateAppartement() {
	appartement app = new appartement("B4.4","4");
	appartementRepository.save(app);
	}
	
	 @Test
	 public void testFindAppartement()
	 {
	 appartement app = appartementRepository.findById(1L).get(); 
	 System.out.println(app);
	 }
	 @Test
	 public void testUpdateProduit()
	 {
		 appartement app = appartementRepository.findById(1L).get();
	 app.setNiveau("2");
	 appartementRepository.save(app);
	 }
	 
	 @Test
	 public void testDeleteAppartement()
	 {
	 appartementRepository.deleteById(1L);;
	 }
	  
	 @Test
	 public void testListerTousAppartements()
	 {
	 List<appartement> apps = appartementRepository.findAll();
	 for (appartement app : apps)
	 {
	 System.out.println(app);
	 }
	 }
	 
	 @Test
	 public void testFindByNomApp()
	 {
	 List<appartement> apps = appartementRepository.findByNomApp("BR2");
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 }
	 }
	 @Test
	 public void testFindByNomAppContains ()
	 {
	 List<appartement> apps=appartementRepository.findByNomAppContains("B");
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 } }
	 
	 @Test
	 public void testfindByNomNiveau()
	 {
	 List<appartement> apps = appartementRepository.findByNomNiveau("4", "B4.4");
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 }
	 }
	 @Test
	 public void testfindByImmeuble()
	 {
	 immeuble im = new immeuble();
	 im.setIdIm(1L);
	 List<appartement> apps = appartementRepository.findByImmeuble(im);
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 }
	 }
	 @Test
	 public void testfindByImmeubleIdIm()
	 {
	 List<appartement> apps = appartementRepository.findByImmeubleIdIm(1L);
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 }
	  }
	 
	 @Test
	 public void testfindByOrderByNomAppAsc()
	 {
	 List<appartement> apps =  appartementRepository.findByOrderByNomAppAsc();
	 for (appartement p : apps)
	 {
	 System.out.println(p);
	 }
	 }

	 @Test
	 public void testTrierAppsNomsNiveaux()
	 {
	 List<appartement> prods = appartementRepository.trierAppartementsNomsNiveaux();
	 for (appartement p : prods)
	 {
	 System.out.println(p);
	 }
	 }

}
