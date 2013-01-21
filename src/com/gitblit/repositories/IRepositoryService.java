package com.gitblit.repositories;

import java.util.Collection;
import java.util.List;

import com.gitblit.GitBlitException;
import com.gitblit.models.RepositoryModel;
import com.gitblit.models.UserModel;

public interface IRepositoryService {
	public void updateRepositoryModel(String repositoryName,
			RepositoryModel repository, boolean isCreate)
			throws GitBlitException;

	public List<RepositoryModel> getRepositoryModels(UserModel user);

	public Collection<RepositoryModel> getRepositoryListCacheValues();
}
