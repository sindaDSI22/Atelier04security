package com.sinda.produits.restcontrollers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sinda.produits.entities.appartement;
import com.sinda.produits.service.AppartementService;

@RestController
@RequestMapping("/api")
@CrossOrigin
public class AppartementRESTController {
		@Autowired
		 AppartementService appartementService;
		@RequestMapping(path ="/all", method = RequestMethod.GET)
		public List<appartement> getAllAppartements() {
		return appartementService.getAllAppartements();
		}
	
@RequestMapping(value="/{idApp}",method = RequestMethod.GET)
public appartement getAppartementById(@PathVariable("idApp") Long id) {
 return appartementService.getAppartement(id);
}


@RequestMapping(method = RequestMethod.POST)
public appartement createAppartement(@RequestBody appartement app) {
return appartementService.saveAppartement(app);
}


@RequestMapping(method = RequestMethod.PUT)
public appartement updateAppartement(@RequestBody appartement app) {
return appartementService.updateAppartement(app);
}


@RequestMapping(value="/{id}",method = RequestMethod.DELETE)
public void deleteAppartement(@PathVariable("id") Long id)
{
	appartementService.deleteAppartementById(id);
}


@RequestMapping(value="/appImm/{idImm}",method = RequestMethod.GET)
public List<appartement> getAppartementsByImmId(@PathVariable("idImm") Long idImm) {
return appartementService.findByImmeubleIdIm(idImm);
}


}
