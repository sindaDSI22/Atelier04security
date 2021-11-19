package com.sinda.produits.repos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.sinda.produits.entities.appartement;
import com.sinda.produits.entities.immeuble;

@RepositoryRestResource(path = "rest")
public interface AppartementRepository extends JpaRepository<appartement, Long> {
	List<appartement> findByNomApp(String nom);
	 List<appartement> findByNomAppContains(String nom);
	 
	 /*@Query("select p from appartement p where p.nomApp like %?1 and p.niveau > ?2")
	 List<appartement> findByNomNiveau (String nom, String niveau);*/
	 
	 @Query("select p from appartement p where  p.niveau > :niveau and p.nomApp like %:nom ")
	 List<appartement> findByNomNiveau (@Param("niveau") String niveau ,@Param("nom") String nom);
     
	 @Query("select p from appartement p where p.immeuble = ?1")
	 List<appartement> findByImmeuble (immeuble immeuble);
	 
	 List<appartement> findByImmeubleIdIm(Long id);

	 List<appartement> findByOrderByNomAppAsc();
	 
	 @Query("select p from appartement p order by p.nomApp ASC, p.niveau DESC")
	 List<appartement> trierAppartementsNomsNiveaux ();



}
