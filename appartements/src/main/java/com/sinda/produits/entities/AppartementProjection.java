package com.sinda.produits.entities;

import org.springframework.data.rest.core.config.Projection;

@Projection(name = "nomApp", types = { appartement.class })

public interface AppartementProjection {
	public String getNomApp();

}
